import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { GGUser, JwtPayload } from '../google/interface/gg-auth.interface';
import { Users } from '../user/user.entity';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
  ) {}
  async validateGGUser(ggUser: GGUser): Promise<Users | null> {
    let user = await this.userService.findByEmail(ggUser.email);

    if (user) {
      // Update existing user
      user = await this.userService.update(user.id, {
        firstName: ggUser.firstName,
        lastName: ggUser.lastName,
        picture: ggUser.picture,
        googleId: ggUser.googleId,
      });
    }
    else {
      // Create new user
      user = await this.userService.create({
        email: ggUser.email,
        firstName: ggUser.firstName,
        lastName: ggUser.lastName,
        picture: ggUser.picture,
        googleId: ggUser.googleId,
        provider: 'google',
      });
    }
    return user;
  }

   login(user: Users) {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      firstName: user.firstName ?? '',
      lastName: user.lastName ?? '',
    };
    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        picture: user.picture,
      },
    };
  }

  async validateUser(email: string): Promise<Users | null> {
    const user = await this.userService.findByEmail(email);
    if (!user || !user.isActive) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
