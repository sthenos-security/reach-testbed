/**
 * DeadController — NOT_REACHABLE.
 *
 * This controller has @Controller decorator but is NOT listed in
 * AppModule's controllers[]. NestJS never instantiates or routes to it.
 */
import { Controller, Get, Post, Body } from '@nestjs/common';
import * as _ from 'lodash';

// SECRET: Dead API key (NOT_REACHABLE — controller not in AppModule)
const DEAD_API_KEY = 'ghp_deadDeadDeadDeadDeadDeadDeadDeadDead';

@Controller('dead')
export class DeadController {

  @Post('merge')
  deadMerge(@Body() body: any) {
    /** CVE-2021-23337 (lodash) — NOT_REACHABLE: not in AppModule. */
    return _.merge({}, body);
  }

  @Get('admin')
  deadAdmin() {
    /** SECRET — NOT_REACHABLE: not in AppModule. */
    return { key: DEAD_API_KEY };
  }
}
