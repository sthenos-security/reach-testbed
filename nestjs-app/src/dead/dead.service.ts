/**
 * DeadService — NOT_REACHABLE.
 *
 * This service has @Injectable decorator but is NOT listed in
 * AppModule's providers[]. Never instantiated by NestJS DI.
 */
import { Injectable } from '@nestjs/common';
import * as mysql from 'mysql2';

@Injectable()
export class DeadService {

  deadQuery(input: string) {
    /** CWE-89 — NOT_REACHABLE: service not in AppModule providers. */
    const conn = mysql.createConnection({ host: 'localhost' });
    conn.query(`SELECT * FROM data WHERE val = '${input}'`);
  }
}
