// icare-backend/src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as session from 'express-session';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieParser());
  app.use(session({
    secret: '1234',
    resave: false,
    saveUninitialized: false,
  }));
  app.enableCors(); // Enable CORS if needed
  await app.listen(3000);
}
bootstrap();