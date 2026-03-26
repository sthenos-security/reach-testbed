/**
 * NestJS application bootstrap.
 *
 * NestFactory.create(AppModule) wires all controllers and providers
 * declared in AppModule. Controllers NOT in the module are NOT_REACHABLE.
 */
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();
