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

// Forked from https://github.com/pwFoo/rust-runc/blob/313e6ae5a79b54455b0a242a795c69adf035141a/src/lib.rs

/*
 * Copyright 2020 fsyncd, Berlin, Germany.
 * Additional material, copyright of the containerd authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use time::{serde::rfc3339, OffsetDateTime};

/// Information for runc container
#[derive(Debug, Serialize, Deserialize)]
pub struct Container {
    pub id: String,
    pub pid: usize,
    pub status: String,
    pub bundle: String,
    pub rootfs: String,
    #[serde(with = "rfc3339")]
    pub created: OffsetDateTime,
    pub annotations: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn serde_test() {
        let j = r#"
            {
                "id": "fake",
                "pid": 1000,
                "status": "RUNNING",
                "bundle": "/path/to/bundle",
                "rootfs": "/path/to/rootfs",
                "created": "2024-09-30T07:13:12.122619299Z",
                "annotations": {
                    "foo": "bar"
                }
            }"#;

        let c: Container = serde_json::from_str(j).unwrap();
        assert_eq!(c.id, "fake");
        assert_eq!(c.pid, 1000);
        assert_eq!(c.status, "RUNNING");
        assert_eq!(c.bundle, "/path/to/bundle");
        assert_eq!(c.rootfs, "/path/to/rootfs");
        assert_eq!(c.created, datetime!(2024-09-30 07:13:12.122619299 UTC));
        assert_eq!(c.annotations.get("foo"), Some(&"bar".to_string()));
        assert_eq!(c.annotations.get("bar"), None);
    }
}
