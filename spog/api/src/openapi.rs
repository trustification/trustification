use spog_model::prelude::*;
use v11y_model::search::SearchHitWithDocument;

/// A local copy of [`SearchResult`], required due to <https://github.com/juhaku/utoipa/issues/790>
#[derive(utoipa::ToSchema)]
#[aliases(
    SearchResultSbom = LocalSearchResult<Vec<SbomSummary>>,
    SearchResultVex = LocalSearchResult<Vec<AdvisorySummary>>,
    SearchResultCve = LocalSearchResult<Vec<SearchHitWithDocument>>,
)]
pub struct LocalSearchResult<T> {
    pub result: T,
    pub total: Option<usize>,
}
