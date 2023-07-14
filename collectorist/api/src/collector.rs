
/// Retrieve an SBOM using its identifier.
#[utoipa::path(
get,
tag = "bombastic",
path = "/api/v1/sbom",
responses(
(status = 200, description = "SBOM found"),
(status = NOT_FOUND, description = "SBOM not found in archive"),
(status = BAD_REQUEST, description = "Missing valid id or index entry"),
),
params(
("id" = String, Query, description = "Identifier of SBOM to fetch"),
)
)]
#[get("/sbom")]
async fn query_sbom(
    state: web::Data<SharedState>,
    params: web::Query<IdentifierParams>,
    accept_encoding: web::Header<AcceptEncoding>,
) -> actix_web::Result<impl Responder> {