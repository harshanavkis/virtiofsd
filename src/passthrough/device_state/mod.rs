// Copyright 2024 Red Hat, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::filesystem::SerializableFileSystem;
use crate::passthrough::PassthroughFs;

/// Adds serialization (migration) capabilities to `PassthroughFs`
impl SerializableFileSystem for PassthroughFs {}
