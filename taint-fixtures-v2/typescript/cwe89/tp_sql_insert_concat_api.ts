// Fixture: CWE-89 SQL Injection - TypeScript
// VERDICT: TRUE_POSITIVE
// PATTERN: sql_insert_string_concat_api_data
// SOURCE: api_response
// SINK: db.run
// TAINT_HOPS: 1
// NOTES: TypeChat-style external API data concatenated into SQL INSERT
// REAL_WORLD: microsoft/TypeChat dbInterface.ts insertTracks
export function insertTrack(db: any, trackName: string, artist: string): void {
    // VULNERABLE: API data (track names) concatenated into SQL
    const sql = `INSERT INTO tracks (name, artist) VALUES ('${trackName}', '${artist}')`;
    db.run(sql);
}
