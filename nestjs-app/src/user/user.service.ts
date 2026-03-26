/**
 * UserService — REACHABLE (listed in AppModule providers[]).
 *
 * CWE-89 (SQL injection) — REACHABLE: called from UserController.searchUsers.
 * UNKNOWN: mysql2 imported, connection created, but only safe parameterized
 *          query used in findAll(); the vulnerable concat path is in searchByName.
 */
import { Injectable } from '@nestjs/common';
import * as mysql from 'mysql2';

@Injectable()
export class UserService {

  private pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    database: 'testbed'
  });

  findAll() {
    /** Safe parameterized query — UNKNOWN path for mysql2 CVEs. */
    return new Promise((resolve, reject) => {
      this.pool.query('SELECT * FROM users WHERE active = ?', [1], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
  }

  searchByName(name: string) {
    /**
     * CWE-89: SQL injection — string concatenation with user input.
     * REACHABLE: called from UserController.searchUsers (@Get route).
     */
    return new Promise((resolve, reject) => {
      this.pool.query(
        `SELECT * FROM users WHERE name = '${name}'`,     // CWE REACHABLE
        (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        }
      );
    });
  }
}
