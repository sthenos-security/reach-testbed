// Copyright © 2026 Sthenos Security. All rights reserved.
// ============================================================================
// REACHABLE TEST FILE — DO NOT USE IN PRODUCTION
// Framework: NestJS (TypeScript/JavaScript)
//
// CWE-89  SQL Injection
// CWE-78  OS Command Injection
// CWE-22  Path Traversal
// CWE-79  XSS
// CWE-918 SSRF
// CWE-502 Unsafe Deserialization
//
// NestJS entrypoint model (fundamentally different from Express):
//   @Controller("path") class  +  @Get/@Post method  =  HTTP entrypoint
//   @Injectable() service injected via constructor DI
//   Engine must:
//     1. Recognise @Get/@Post/@Put/@Delete/@Patch on a method as an entrypoint
//     2. Follow constructor DI chain: Controller → Service → Repository
//     3. Resolve @Body(), @Param(), @Query() decorators as user-controlled input
//     4. Handle Guards/Interceptors (do NOT break reachability chain)
//     5. Distinguish @Module() registered controllers from unregistered classes
// ============================================================================
const { exec, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');

// ─── Simulate NestJS decorator metadata ──────────────────────────────────────
// In real NestJS these are TypeScript decorators. We simulate the pattern
// so static analysis has the same structural signal to find.

function Controller(prefix) { return (cls) => { cls.__prefix = prefix; return cls; }; }
function Get(route)    { return (proto, key) => { proto[key].__get = route; }; }
function Post(route)   { return (proto, key) => { proto[key].__post = route; }; }
function Injectable()  { return (cls) => cls; }
function Body()        { return () => null; }
function Param(key)    { return () => null; }
function Query(key)    { return () => null; }


// ─── Service layer — injected into controller ─────────────────────────────────

// @Injectable()
class UserService {
  /**
   * CWE-89 TP: raw SQL in service method called from controller — REACHABLE.
   * Engine must follow DI chain: Controller → Service.findByName()
   */
  findByName(name) {
    const mysql = require('mysql2');
    const pool = mysql.createPool({ host: 'localhost', user: 'root', password: '', database: 'app' });
    return pool.query(`SELECT * FROM users WHERE name = '${name}'`);
  }

  findByIdSafe(id) {
    /**
     * CWE-89 FP: parameterized query — REACHABLE but NOT a vulnerability.
     */
    const mysql = require('mysql2');
    const pool = mysql.createPool({ host: 'localhost', user: 'root', password: '', database: 'app' });
    return pool.query('SELECT * FROM users WHERE id = ?', [parseInt(id, 10)]);
  }

  runCommand(cmd) {
    /** CWE-78 TP: command injection in service — REACHABLE via DI. */
    return execSync(cmd, { encoding: 'utf8' });
  }

  readFile(filename) {
    /** CWE-22 TP: path traversal in service — REACHABLE via DI. */
    return fs.readFileSync(path.join('/srv/files', filename), 'utf8');
  }
}


// ─── Controller — registered in AppModule ────────────────────────────────────

// @Controller('users')
class UserController {
  constructor() {
    this.userService = new UserService(); // DI simulation
  }

  // @Get(':id')
  getUser(id) {
    /**
     * CWE-89 TP: @Param('id') flows to raw SQL — REACHABLE.
     * Call path: GET /users/:id → getUser() → userService.findByName()
     */
    return this.userService.findByName(id);
  }

  // @Get('safe/:id')
  getUserSafe(id) {
    /** CWE-89 FP: safe parameterized path — REACHABLE, not injectable. */
    return this.userService.findByIdSafe(id);
  }

  // @Post('search')
  searchUsers(body) {
    /**
     * CWE-89 TP: @Body() flows to raw SQL — REACHABLE.
     * body.name comes from POST request body.
     */
    return this.userService.findByName(body.name);
  }

  // @Post('exec')
  execCommand(body) {
    /** CWE-78 TP: @Body().cmd flows to execSync — REACHABLE. */
    return this.userService.runCommand(body.cmd);
  }

  // @Get('file')
  getFile(query) {
    /** CWE-22 TP: @Query('filename') flows to fs.readFileSync — REACHABLE. */
    return this.userService.readFile(query.filename);
  }

  // @Get('ssrf')
  fetchUrl(query) {
    /**
     * CWE-918 TP: SSRF — user-controlled URL via @Query() — REACHABLE.
     */
    return new Promise((resolve, reject) => {
      https.get(query.url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ data }));
      }).on('error', reject);
    });
  }
}


// ─── Unregistered controller — NOT_REACHABLE ─────────────────────────────────

// @Controller('admin')
class AdminController {
  /**
   * NOT_REACHABLE — AdminController is not registered in AppModule.
   * Engine must check @Module({ controllers: [...] }) to determine this.
   */

  // @Get('users')
  getAllUsers(query) {
    const mysql = require('mysql2');
    const pool = mysql.createPool({ host: 'localhost', user: 'root', password: '', database: 'app' });
    pool.query(`SELECT * FROM users WHERE role = '${query.role}'`);
  }

  // @Post('exec')
  dangerousExec(body) {
    exec(body.cmd, (err, stdout) => console.log(stdout));
  }
}


// ─── Module — engine reads controllers array to build entrypoint set ─────────

const AppModule = {
  controllers: [UserController],
  providers:   [UserService],
  // AdminController intentionally excluded
};

module.exports = { UserController, UserService, AdminController, AppModule };
