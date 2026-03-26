/**
 * UserController — REACHABLE (listed in AppModule controllers[]).
 *
 * CVE-2021-23337 (lodash prototype pollution) — REACHABLE: _.merge called.
 * CVE-2022-23529 (jsonwebtoken) — REACHABLE: jwt.verify called.
 * CWE-89 (SQL injection) — REACHABLE: string concat in query.
 * SECRET — REACHABLE: JWT_SECRET hardcoded.
 */
import { Controller, Get, Post, Body, Query } from '@nestjs/common';
import { UserService } from './user.service';
import * as _ from 'lodash';
import * as jwt from 'jsonwebtoken';

// SECRET: Hardcoded JWT secret (REACHABLE — used in verify endpoint)
const JWT_SECRET = 'nestjs-super-secret-jwt-key-testbed';

@Controller('users')
export class UserController {

  constructor(private readonly userService: UserService) {}

  @Get()
  findAll() {
    /** GET /users — REACHABLE (auto-wired by @Controller + @Get). */
    return this.userService.findAll();
  }

  @Post('merge')
  mergeData(@Body() body: any) {
    /**
     * POST /users/merge — REACHABLE.
     * CVE-2021-23337 (lodash prototype pollution): _.merge with user input.
     */
    const base = { role: 'user' };
    const merged = _.merge(base, body);                    // CVE REACHABLE
    return merged;
  }

  @Post('verify')
  verifyToken(@Body('token') token: string) {
    /**
     * POST /users/verify — REACHABLE.
     * CVE-2022-23529 (jsonwebtoken algorithm confusion).
     */
    const payload = jwt.verify(token, JWT_SECRET);         // CVE REACHABLE
    return { user: payload };
  }

  @Get('search')
  searchUsers(@Query('name') name: string) {
    /**
     * GET /users/search?name=... — REACHABLE.
     * CWE-89: SQL injection via UserService.
     */
    return this.userService.searchByName(name);            // CWE REACHABLE
  }

  // ═══════════════════════════════════════════════════════════════
  // TYPE B DEAD CODE — method in live controller, but not decorated
  // with @Get/@Post so NestJS never registers it as an endpoint.
  // The class IS instantiated (it's in AppModule), but this method
  // has no route and is never called from any other method.
  // ═══════════════════════════════════════════════════════════════

  /**
   * NOT_REACHABLE (Type B): method in registered controller, no decorator, never called.
   * CWE-78 (command injection) — NOT_REACHABLE.
   */
  deadInlineExec(cmd: string): string {
    const { execSync } = require('child_process');
    return execSync(cmd).toString();                       // CWE-78 NOT_REACHABLE (Type B)
  }
}
