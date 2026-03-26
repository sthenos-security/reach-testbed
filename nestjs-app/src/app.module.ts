/**
 * AppModule — the root NestJS module.
 *
 * Controllers listed in controllers[] are REACHABLE.
 * Providers listed in providers[] are REACHABLE.
 * Classes NOT listed here are NOT_REACHABLE.
 */
import { Module } from '@nestjs/common';
import { UserController } from './user/user.controller';
import { UserService } from './user/user.service';

// NOTE: DeadController and DeadService are intentionally NOT imported or listed.

@Module({
  controllers: [UserController],      // REACHABLE
  providers: [UserService],            // REACHABLE
})
export class AppModule {}
