use std::{
    collections::VecDeque,
    io::{ErrorKind, Result},
    net::SocketAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use env_logger::Env;
use ircie::{
    system_params::{Context, ResMut},
    Irc,
};

use log::{debug, error, info, trace};
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::StdRng,
    Rng, SeedableRng,
};
use serde::Deserialize;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{
        mpsc::{self},
        RwLock,
    },
    task::JoinHandle,
};

const MAX_MSG_LEN: usize = 512;

#[derive(Deserialize)]
struct Config {
    host: String,
    hostname: String,
    port: u16,
    ircd_name: String,
    banner_filepath: String,
    chan_name: String,
    privmsg_line: String,
}

impl Config {
    pub async fn load(path: &str) -> Result<Self> {
        let mut file = File::open(path).await?;
        let mut content = String::new();
        file.read_to_string(&mut content).await?;

        let config: Self = serde_yaml::from_str(&content).unwrap();

        Ok(config)
    }
}

#[derive(Clone)]
struct Ircd {
    host: String,
    port: u16,
    hostname: String,
    name: String,
    motd: Vec<String>,
    chan_name: String,
    privmsg_line: String,
}

struct Nerd(mpsc::Receiver<Nick>);

struct IrcClient<T> {
    addr: SocketAddr,
    read_task: JoinHandle<T>,
    write_task: JoinHandle<T>,
    rx: mpsc::Receiver<bool>,
    reporting_tx: mpsc::Sender<Nick>,
    send_queue: Arc<RwLock<VecDeque<String>>>,
    recv_queue: Arc<RwLock<VecDeque<String>>>,
    ircd: Ircd,
    server_created_on: String,
    global_users: u32,
    global_invisibles: u32,
    global_servers: u32,
    total_ircops: u32,
    total_unknown_conns: u32,
    total_channels: u32,
    local_users: u32,
    local_servers: u32,
    max_local_users: u32,
    max_global_users: u32,
    highest_conn_count: u32,
    total_conns_received: u32,

    nick: Option<Nick>,
    user: Option<User>,
    welcomed: bool,
    quit: bool,
}

#[derive(Clone)]
pub struct Nick(pub String);

impl Deref for Nick {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Nick {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[allow(dead_code)]
pub struct User {
    username: String,
    hostname: String,
    servername: String,
    realname: String,
}

impl<T> IrcClient<T> {
    pub fn new(
        addr: SocketAddr,
        send_queue: Arc<RwLock<VecDeque<String>>>,
        recv_queue: Arc<RwLock<VecDeque<String>>>,
        ircd: Ircd,
        read_task: JoinHandle<T>,
        write_task: JoinHandle<T>,
        rx: mpsc::Receiver<bool>,
        reporting_tx: mpsc::Sender<Nick>,
    ) -> Self {
        let mut rng = rand::thread_rng();

        let global_users = rng.gen_range(200..8000);
        let global_invisibles = rng.gen_range(100..global_users);
        let global_servers = rng.gen_range(2..20);
        let total_ircops = rng.gen_range(10..(global_users / 10));
        let total_unknown_conns = rng.gen_range(1..10);
        let total_channels =
            rng.gen_range((global_users / 30)..((global_users as f32 * 1.5) as u32));
        let local_users = rng.gen_range((global_users / 20)..(global_users / 2));
        let local_servers = rng.gen_range(1..global_servers);
        let max_local_users = rng.gen_range(local_users..(local_users * 2));
        let max_global_users = rng.gen_range(max_local_users..(max_local_users * 2));
        let highest_conn_count = rng.gen_range((max_local_users - 10)..max_local_users + 10);
        let total_conns_received =
            rng.gen_range((highest_conn_count * 100)..(highest_conn_count * 1000));

        Self {
            addr,
            read_task,
            write_task,
            rx,
            reporting_tx,
            send_queue: send_queue,
            recv_queue: recv_queue,
            ircd,
            server_created_on: "Sun May 24 2020 at 03:31:19 UTC".to_owned(),
            global_users,
            global_invisibles,
            global_servers,
            total_ircops,
            total_unknown_conns,
            total_channels,
            local_users,
            local_servers,
            max_local_users,
            max_global_users,
            highest_conn_count,
            total_conns_received,
            nick: None,
            user: None,
            welcomed: false,
            quit: false,
        }
    }

    async fn queue(&mut self, data: impl AsRef<str>) {
        // do not use this trace if you have get_fucked() executing
        //trace!(">> {}", data.as_ref());
        self.send_queue
            .write()
            .await
            .push_back(format!("{}\r\n", data.as_ref()));
    }

    pub async fn process(&mut self) -> Result<()> {
        self.connection().await?;

        loop {
            if self.quit {
                self.quit();
                return Ok(());
            }

            if let Ok(should_quit) = self.rx.try_recv() {
                if should_quit {
                    self.quit();
                    return Ok(());
                }
            }

            self.process_line().await;
        }
    }

    async fn process_line(&mut self) {
        let Some(line) = self.recv_queue.write().await.pop_front() else { return; };
        trace!("<< {}", line);
        self.handle(&line).await;
    }

    async fn connection(&mut self) -> Result<()> {
        self.queue("NOTICE AUTH :*** Looking up your hostname...")
            .await;

        self.queue("NOTICE AUTH :*** Checking ident").await;
        self.queue("NOTICE AUTH :*** Found your hostname").await;

        Ok(())
    }

    async fn handle(&mut self, line: &str) {
        let args = line.split_whitespace().collect::<Vec<_>>();

        match args[0].to_uppercase().as_str() {
            "USER" => self.user(args[1], args[2], args[3], args[4]).await,
            "NICK" => self.nick(args[1]).await,
            "CAP" => self.cap_ls_302(args[1]).await,
            "PING" => self.pong(args[1]).await,
            "QUIT" => self.quit = true,
            _ => {}
        }
    }

    fn quit(&mut self) {
        info!(
            "{}:{} -> connection closed.",
            self.addr.ip().to_string(),
            self.addr.port()
        );
        self.read_task.abort();
        self.write_task.abort();
    }

    async fn pong(&mut self, val: &str) {
        self.queue(format!(
            ":{} PONG {} :{}",
            self.ircd.hostname, self.ircd.hostname, val
        ))
        .await;
    }

    async fn cap_ls_302(&mut self, cmd: &str) {
        if cmd == "LS" {
            self.queue(format!(":{} CAP * LS :multi-prefix", self.ircd.hostname))
                .await;
            return;
        }
        if cmd == "REQ" {
            self.queue(format!(":{} CAP * ACK :multi-prefix", self.ircd.hostname))
                .await;
            return;
        }
    }

    async fn user(&mut self, username: &str, hostname: &str, servername: &str, realname: &str) {
        self.user = Some(User {
            username: username.to_owned(),
            hostname: hostname.to_owned(),
            servername: servername.to_owned(),
            realname: realname.to_owned(),
        });
        self.maybe_welcome().await;
    }

    async fn nick(&mut self, nick: &str) {
        self.nick = Some(Nick(nick.to_owned()));
        self.maybe_welcome().await;
    }

    async fn maybe_welcome(&mut self) {
        if self.nick.is_none() || self.user.is_none() || self.welcomed {
            return;
        }

        self.queue("NOTICE AUTH :*** No Ident response").await;

        self.queue(format!(
            ":{} 001 {} :Welcome to the EFnet Internet Relay Chat Network bob",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0
        ))
        .await;

        self.queue(format!(
            ":{} 002 {} :Your host is {}[{}/{}], running version {}",
            self.ircd.hostname,
            self.ircd.host,
            self.ircd.port,
            self.nick.as_ref().unwrap().0,
            self.ircd.hostname,
            self.ircd.name
        ))
        .await;

        self.queue(&format!(
            ":{} 003 {} :This server was created {}",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.server_created_on
        ))
        .await;

        self.queue(&format!(
            ":{} 004 {} :{} {} oiwszcrkfydnxbauglZCD biklmnopstveIrS bkloveI",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.ircd.hostname,
            self.ircd.name
        ))
        .await;

        self.queue(
            &format!(
                ":{} 005 {} CHANTYPES=&# EXCEPTS INVEX CHANMODES=eIb,k,l,imnpstS CHANLIMIT=&#:75 PREFIX=(ov)@+ MAXLIST=beI:100 MODES=4 NETWORK=EFnet KNOCK STATUSMSG=@+ CALLERID=g :are supported by this server",
                self.ircd.hostname, self.nick.as_ref().unwrap().0
            ),
        )
        .await;

        self.queue(
            &format!(
                ":{} 005 {} SAFELIST ELIST=U CASEMAPPING=rfc1459 CHARSET=ascii NICKLEN=9 CHANNELLEN=50 TOPICLEN=160 ETRACE CPRIVMSG CNOTICE DEAF=D MONITOR=60 :are supported by this server",
                self.ircd.hostname, self.nick.as_ref().unwrap().0
            ),
        )
        .await;

        self.queue(
            &format!(
                ":{} 005 {} FNC ACCEPT=20 MAP TARGMAX=NAMES:1,LIST:1,KICK:1,WHOIS:1,PRIVMSG:4,NOTICE:4,ACCEPT:,MONITOR: :are supported by this server",
                self.ircd.hostname, self.nick.as_ref().unwrap().0
            ),
        )
        .await;

        self.queue(&format!(
            ":{} 251 {} :There are {} users and {} invisible on {} servers",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.global_users,
            self.global_invisibles,
            self.global_servers
        ))
        .await;

        self.queue(&format!(
            ":{} 252 {} {} :IRC Operators online",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.total_ircops
        ))
        .await;

        self.queue(&format!(
            ":{} 253 {} {} :Unknown connection(s)",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.total_unknown_conns
        ))
        .await;

        self.queue(&format!(
            ":{} 254 {} {} :channels formed",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.total_channels
        ))
        .await;

        self.queue(&format!(
            ":{} 255 {} :I have {} clients and {} servers",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.local_users,
            self.local_servers
        ))
        .await;

        self.queue(&format!(
            ":{} 265 {} {} {} :Current local users {}, max {}",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.local_users,
            self.max_local_users,
            self.local_users,
            self.max_local_users
        ))
        .await;

        self.queue(&format!(
            ":{} 266 {} {} {} :Current global users {}, max {}",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.global_users + self.global_invisibles,
            self.max_global_users,
            self.global_users + self.global_invisibles,
            self.max_global_users
        ))
        .await;

        self.queue(&format!(
            ":{} 250 {} :Highest connection count: {} ({} clients) ({} connections received)",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.highest_conn_count,
            self.max_local_users,
            self.total_conns_received
        ))
        .await;

        self.welcomed = true;
        self.get_fucked().await;
    }

    async fn get_fucked(&mut self) {
        let mut rng = StdRng::from_entropy();

        info!(
            "I'm fucking the shit out of {} ({}:{}) right now...",
            self.nick.as_ref().unwrap().0,
            self.addr.ip().to_string(),
            self.addr.port()
        );

        self.reporting_tx
            .send(self.nick.clone().unwrap())
            .await
            .ok();

        loop {
            if let Ok(should_quit) = self.rx.try_recv() {
                if should_quit {
                    self.quit();
                    return;
                }
            }

            if rng.gen_bool(1. / 5.) {
                self.motd().await;
            }

            let chan = Alphanumeric.sample_string(&mut rng, 6)
                + "-"
                + &self.ircd.chan_name
                + "-"
                + &Alphanumeric.sample_string(&mut rng, 6);

            self.queue(format!(
                ":{}!{}@{} JOIN #{}",
                self.nick.as_ref().unwrap().0,
                self.user.as_ref().unwrap().username,
                self.user.as_ref().unwrap().hostname,
                chan
            ))
            .await;

            let msg = format!(
                ":FUCKYOU{}!B@STARD PRIVMSG #{} :\x03{} {} {}",
                self.nick.as_ref().unwrap().0,
                chan,
                rng.gen_range(2..14),
                self.nick.as_ref().unwrap().0,
                self.ircd.privmsg_line
            );

            self.queue(msg).await;
        }
    }

    async fn motd(&mut self) {
        self.queue(&format!(
            ":{} 375 {} :- {} Message of the Day -",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0,
            self.ircd.hostname
        ))
        .await;

        for line in self.ircd.motd.clone() {
            self.queue(&format!(
                ":{} 372 {} : {}",
                self.ircd.hostname,
                self.nick.as_ref().unwrap().0,
                line
            ))
            .await;
        }

        self.queue(&format!(
            ":{} 376 {} :End of /MOTD command.",
            self.ircd.hostname,
            self.nick.as_ref().unwrap().0
        ))
        .await;
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("fuckircd - made by wrk.");

    let config = Config::load("config.yaml").await?;

    if !std::path::Path::new(&config.banner_filepath).exists() {
        error!(
            "motd file '{}` doesn't exists. please make it.",
            config.banner_filepath
        );
        return Ok(());
    }

    let mut banner_file = File::open(&config.banner_filepath).await.unwrap();
    let mut content = vec![];
    banner_file.read_to_end(&mut content).await.unwrap();

    let motd = content
        .split(|&c| c == 0x0a)
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .map(|line| String::from_utf8_lossy(line).to_string())
        .collect::<Vec<_>>();

    let ircd = Ircd {
        host: config.host.clone(),
        port: config.port,
        hostname: config.hostname.clone(),
        name: config.ircd_name,
        motd,
        chan_name: config.chan_name.clone(),
        privmsg_line: config.privmsg_line.clone(),
    };

    let (reporting_tx, reporting_rx) = mpsc::channel(1);

    let mut reporting = Irc::from_config("reporting_config.yaml").await?;

    reporting
        .add_resource(Nerd(reporting_rx))
        .await
        .add_interval_task(Duration::from_millis(50), report_fucker)
        .await;

    let listener = TcpListener::bind(format!("{}:{}", ircd.host, ircd.port)).await?;

    info!("Starting reporting bot.");
    tokio::task::spawn(async move { reporting.run().await.unwrap() });

    info!("Listening on {}:{}", ircd.host, ircd.port);

    loop {
        let (socket, addr) = listener.accept().await?;

        info!(
            "Got connexion from {}:{}",
            addr.ip().to_string(),
            addr.port()
        );

        let (mut reader, mut writer) = tokio::io::split(socket);
        let send_queue = Arc::new(RwLock::new(VecDeque::<String>::new()));
        let recv_queue = Arc::new(RwLock::new(VecDeque::<String>::new()));

        let cloned_send_queue = send_queue.clone();
        let cloned_recv_queue = recv_queue.clone();

        let (write_tx, rx) = mpsc::channel(1);

        let read_tx = write_tx.clone();

        // WRITE TASK
        let write_task = tokio::task::spawn(async move {
            loop {
                let len;
                {
                    let queue = cloned_send_queue.read().await;
                    len = queue.len();
                }
                if len == 0 {
                    continue;
                }
                let mut queue = cloned_send_queue.write().await;
                let msg = queue.pop_front().unwrap();

                let bytes_written = match writer.write(msg.as_bytes()).await {
                    Ok(bytes_written) => bytes_written,
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock => {
                            continue;
                        }
                        _ => {
                            write_tx.send(true).await.unwrap();
                            break;
                        }
                    },
                };

                if bytes_written == 0 {
                    write_tx.send(true).await.unwrap();
                    break;
                }

                if bytes_written < msg.len() {
                    queue.push_front(msg[bytes_written..].to_owned());
                }
            }
        });

        // READ TASK
        let read_task = tokio::task::spawn(async move {
            let mut partial_line = String::new();

            loop {
                let mut buf = [0; MAX_MSG_LEN];
                let mut lines = vec![];
                let bytes_read = match reader.read(&mut buf).await {
                    Ok(bytes_read) => bytes_read,
                    Err(err) => match err.kind() {
                        ErrorKind::WouldBlock => {
                            continue;
                        }
                        _ => {
                            read_tx.send(true).await.unwrap();
                            break;
                        }
                    },
                };

                if bytes_read == 0 {
                    read_tx.send(true).await.unwrap();
                    break;
                }

                let buf = &buf[..bytes_read];

                let buf_str: String =
                    partial_line + String::from_utf8_lossy(buf).into_owned().as_str();

                partial_line = String::new();

                let new_lines: Vec<&str> = buf_str.split("\n").collect();
                let len = new_lines.len();

                for (index, line) in new_lines.into_iter().enumerate() {
                    if index == len - 1 && &buf[buf.len() - 1..] != b"\n" {
                        partial_line = line.to_owned();
                        break;
                    }
                    if line.len() != 0 {
                        lines.push(line.to_owned());
                    }
                }
                let mut queue = cloned_recv_queue.write().await;
                queue.append(&mut lines.into());
            }
        });

        let cloned_ircd = ircd.clone();
        let cloned_reporting_tx = reporting_tx.clone();
        tokio::task::spawn(async move {
            IrcClient::new(
                addr,
                send_queue,
                recv_queue,
                cloned_ircd,
                read_task,
                write_task,
                rx,
                cloned_reporting_tx,
            )
            .process()
            .await
            .ok();
        });
    }
}

fn report_fucker(mut ctx: Context, mut nerd: ResMut<Nerd>) {
    //TODO: Add ircie config access to systems.

    if let Ok(nerd_nick) = nerd.0.try_recv() {
        debug!("Sending report to #dev...");

        ctx.privmsg(
            "#dev",
            &format!("I'm fucking with {} right now.", nerd_nick.0),
        );
    }
}
