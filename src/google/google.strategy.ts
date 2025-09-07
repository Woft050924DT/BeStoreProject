/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback, Profile } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    super({
      clientID: configService.get<string>('GG_CLIENT_ID'),
      clientSecret: configService.get<string>('GG_SECRET'),
      callbackURL: configService.get<string>('GG_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<void> {
    try {
      const { name, emails, photos, id } = profile;

      const user = {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        email: emails[0].value,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        fullName: `${name.givenName || ''} ${name.familyName || ''}`.trim(),
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        picture: photos[0].value,
        googleId: id,
        accessToken,
      };

      const validatedUser = await this.authService.validateGGUser(user);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call
      done(null, validatedUser);
    } catch (error) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-call
      done(error, null);
    }
  }
}
