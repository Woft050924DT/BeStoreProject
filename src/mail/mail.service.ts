// src/mail/mail.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  constructor(private configService: ConfigService) {}

  sendVerificationEmail(email: string, token: string): void {
    const verificationUrl = `${this.configService.get('FRONTEND_URL')}/auth/verify-email?token=${token}`;
    

    console.log(`Verification email sent to ${email}: ${verificationUrl}`);
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl = `${this.configService.get('FRONTEND_URL')}/auth/reset-password?token=${token}`;
    
    console.log(`Password reset email sent to ${email}: ${resetUrl}`);
  }
}