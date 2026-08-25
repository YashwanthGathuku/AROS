use std::sync::Arc;

use aros_types::ResourceBudgets;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("experiment concurrency limit reached")]
    ExperimentLimit,
    #[error("operation timed out")]
    Timeout,
    #[error("cancelled")]
    Cancelled,
}

/// Bounded concurrency derived from the frozen authorization manifest.
pub struct BudgetGovernor {
    pub budgets: ResourceBudgets,
    experiments: Arc<Semaphore>,
    sandboxes: Arc<Semaphore>,
    cells: Arc<Semaphore>,
}

impl BudgetGovernor {
    pub fn new(budgets: ResourceBudgets) -> Self {
        Self {
            experiments: Arc::new(Semaphore::new(budgets.max_concurrent_experiments as usize)),
            sandboxes: Arc::new(Semaphore::new(budgets.max_sandbox_instances as usize)),
            cells: Arc::new(Semaphore::new(budgets.max_research_cells as usize)),
            budgets,
        }
    }

    pub async fn acquire_experiment(
        &self,
    ) -> Result<tokio::sync::SemaphorePermit<'_>, BudgetError> {
        self.experiments
            .try_acquire()
            .map_err(|_| BudgetError::ExperimentLimit)
    }

    pub fn remaining_experiments(&self) -> usize {
        self.experiments.available_permits()
    }

    pub async fn with_timeout<F, T>(&self, fut: F) -> Result<T, BudgetError>
    where
        F: std::future::Future<Output = T>,
    {
        timeout(Duration::from_millis(self.budgets.wall_time_ms), fut)
            .await
            .map_err(|_| BudgetError::Timeout)
    }

    pub fn sandbox_limit(&self) -> u32 {
        self.budgets.max_sandbox_instances
    }

    pub fn remaining_sandboxes(&self) -> usize {
        self.sandboxes.available_permits()
    }

    pub fn cell_permits(&self) -> usize {
        self.cells.available_permits()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_unbounded_experiments() {
        let budgets = ResourceBudgets {
            max_concurrent_experiments: 1,
            ..ResourceBudgets::default()
        };
        let gov = BudgetGovernor::new(budgets);
        let _p1 = gov.acquire_experiment().await.unwrap();
        assert!(gov.acquire_experiment().await.is_err());
    }
}
