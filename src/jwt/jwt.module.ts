import { Module } from '@nestjs/common';
import { JwtService } from './jwt.service';
import { JwtController } from './jwt.controller';
import { JwtAuthGuard } from './jwt-auth.guard';

@Module({
  controllers: [JwtController],
  providers: [JwtService, JwtAuthGuard],
  exports: [JwtAuthGuard],
})
export class JwtModule {}
