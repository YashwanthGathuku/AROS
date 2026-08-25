use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, TypesError};

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            pub fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = TypesError;

            fn from_str(s: &str) -> Result<Self> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|e| TypesError::InvalidId(format!("{}: {e}", stringify!($name))))
            }
        }
    };
}

typed_id!(CampaignId);
typed_id!(TargetId);
typed_id!(SnapshotId);
typed_id!(SandboxId);
typed_id!(HypothesisId);
typed_id!(ExperimentId);
typed_id!(FindingId);
typed_id!(ArtifactId);
typed_id!(VerifierRunId);
typed_id!(PatchId);
typed_id!(ReattackId);
typed_id!(RegressionId);
typed_id!(NodeId);
typed_id!(EdgeId);
typed_id!(RequestId);
typed_id!(WorkerId);
typed_id!(RunId);
