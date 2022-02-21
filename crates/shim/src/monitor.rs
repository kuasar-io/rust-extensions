/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

use std::collections::HashMap;
use std::fmt;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

use lazy_static::lazy_static;
use log::{error, warn};

use crate::error::Result;

lazy_static! {
    pub static ref MONITOR: Mutex<Monitor> = {
        let monitor = Monitor {
            seq_id: 0,
            subscribers: HashMap::new(),
            topic_subs: HashMap::new(),
        };
        Mutex::new(monitor)
    };
}

pub fn monitor_subscribe(topic: Topic) -> Result<Subscription> {
    let mut monitor = MONITOR.lock().unwrap();
    let s = monitor.subscribe(topic)?;
    Ok(s)
}

pub fn monitor_notify_by_pid(pid: i32, exit_code: i32) -> Result<()> {
    let monitor = MONITOR.lock().unwrap();
    monitor.notify_by_pid(pid, exit_code)
}

pub fn monitor_notify_by_exec(id: &str, exec_id: &str, exit_code: i32) -> Result<()> {
    let monitor = MONITOR.lock().unwrap();
    monitor.notify_by_exec(id, exec_id, exit_code)
}

pub struct Monitor {
    pub(crate) seq_id: i64,
    pub(crate) subscribers: HashMap<i64, Subscriber>,
    pub(crate) topic_subs: HashMap<Topic, Vec<i64>>,
}

pub(crate) struct Subscriber {
    pub(crate) topic: Topic,
    pub(crate) tx: Sender<ExitEvent>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub enum Topic {
    Pid(i32),
    Exec(String, String),
    All,
}

pub struct Subscription {
    pub id: i64,
    pub rx: Receiver<ExitEvent>,
}

#[derive(Debug)]
pub struct ExitEvent {
    // what kind of a thing exit
    pub subject: Subject,
    pub exit_code: i32,
}

impl fmt::Display for ExitEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.subject {
            Subject::Pid(pid) => {
                write!(f, "PID {} exit with code {}", pid, self.exit_code)
            }
            Subject::Exec(cid, eid) => {
                write!(
                    f,
                    "EXEC process {} inside {} exit with code {}",
                    eid, cid, self.exit_code
                )
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum Subject {
    // process pid
    Pid(i32),
    // exec with containerd id and exec id for vm container,
    // if exec is empty, then the event is for the container
    Exec(String, String),
}

impl Monitor {
    pub fn subscribe(&mut self, topic: Topic) -> Result<Subscription> {
        let (tx, rx) = channel::<ExitEvent>();
        let id = self.seq_id;
        self.seq_id += 1;
        let subscriber = Subscriber {
            tx,
            topic: topic.clone(),
        };
        self.subscribers.insert(id, subscriber);
        self.topic_subs
            .entry(topic)
            .or_insert_with(Vec::new)
            .push(id);
        Ok(Subscription { id, rx })
    }

    pub fn notify_by_pid(&self, pid: i32, exit_code: i32) -> Result<()> {
        let topic = Topic::Pid(pid);
        let subject = Subject::Pid(pid);
        self.notify_topic(&topic, &subject, exit_code);
        self.notify_topic(&Topic::All, &subject, exit_code);
        Ok(())
    }

    pub fn notify_by_exec(&self, cid: &str, exec_id: &str, exit_code: i32) -> Result<()> {
        let topic = Topic::Exec(cid.into(), exec_id.into());
        let subject = Subject::Exec(cid.into(), exec_id.into());
        self.notify_topic(&topic, &subject, exit_code);
        self.notify_topic(&Topic::All, &subject, exit_code);
        Ok(())
    }

    fn notify_topic(&self, topic: &Topic, subject: &Subject, exit_code: i32) {
        self.topic_subs.get(topic).map_or((), |subs| {
            for i in subs {
                self.subscribers.get(i).and_then(|sub| {
                    sub.tx
                        .send(ExitEvent {
                            subject: subject.clone(),
                            exit_code,
                        })
                        .map_err(|e| warn!("failed to send {}", e))
                        .ok()
                });
            }
        })
    }

    pub fn unsubscribe(&mut self, id: i64) -> Result<()> {
        let sub = self.subscribers.remove(&id);
        if let Some(s) = sub {
            self.topic_subs.get_mut(&s.topic).map(|v| {
                v.iter().position(|&x| x == id).map(|i| {
                    v.remove(i);
                })
            });
            let subs = self.topic_subs.get(&s.topic);
            if let Some(v) = subs {
                if v.is_empty() {
                    self.topic_subs.remove(&s.topic);
                }
            }
        }
        Ok(())
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let mut monitor = MONITOR.lock().unwrap();
        monitor.unsubscribe(self.id).unwrap_or_else(|e| {
            error!("failed to unsubscribe the subscription {}, {}", self.id, e);
        });
    }
}
