import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { GGUser, JwtPayload } from '../google/interface/gg-auth.interface';
import { Users } from '../user/user.entity';
import { RegisterDto } from './interface/register.dto';
import { LoginDto } from './interface/login.dto';
import { ChangePasswordDto } from './interface/changePassword.dto';
import { ResetPasswordDto } from './interface/resetPassword.dto';
import { ForgotPasswordDto } from './interface/forgotPassword.dto';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';
import { MailService } from '../mail/mail.service';
import { AuthProvider } from '../models/enum/authProvider.enum';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
    private readonly mailService: MailService,
  ) {}

  // Đăng ký tài khoản mới
  async register(
    registerDto: RegisterDto,
  ): Promise<{ message: string; user: Partial<Users> }> {
    const { email, password, username, fullName } = registerDto;

    // Kiểm tra email đã tồn tại
    const existingUser = await this.userService.findByEmail(email);
    if (existingUser) {
      throw new ConflictException('Email đã được sử dụng');
    }

    // Kiểm tra username đã tồn tại
    const existingUsername = await this.userService.findByUsername(username);
    if (existingUsername) {
      throw new ConflictException('Username đã được sử dụng');
    }

    // Tạo token xác thực email
    const emailVerificationToken = randomBytes(32).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // Hết hạn sau 24 giờ

    // Tạo user mới
    const user = await this.userService.create({
      email,
      password,
      fullName,
      provider: AuthProvider.LOCAL,
      emailVerificationToken,
      emailVerificationExpires, // Thêm thời hạn token
      emailVerified: false,
    });

    void this.mailService.sendVerificationEmail(user.email, emailVerificationToken);

    return {
      message:
        'Đăng ký thành công. Vui lòng kiểm tra email để xác thực tài khoản.',
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
      },
    };
  }

  // Đăng nhập bằng email/mật khẩu
  async login(
    loginDto: LoginDto,
  ): Promise<{ access_token: string; user: Partial<Users> }> {
    const { email, password } = loginDto;

    // Xác thực email và mật khẩu
    const user = await this.validateLocalUser(email, password);
    if (!user) {
      throw new UnauthorizedException('Email hoặc mật khẩu không đúng');
    }

    // Kiểm tra xác thực email
    if (!user.emailVerified && user.provider === AuthProvider.LOCAL) {
      throw new UnauthorizedException(
        'Vui lòng xác thực email trước khi đăng nhập',
      );
    }

    // Kiểm tra trạng thái tài khoản
    if (!user.isActive) {
      throw new UnauthorizedException('Tài khoản đã bị vô hiệu hóa');
    }

    return this.generateTokenResponse(user);
  }

  // Xác thực user bằng email và mật khẩu
  async validateLocalUser(
    email: string,
    password: string,
  ): Promise<Users | null> {
    const user = await this.userService.findByEmail(email);
    if (
      user &&
      user.provider === AuthProvider.LOCAL &&
      user.password &&
      (await bcrypt.compare(password, user.password))
    ) {
      return user;
    }
    return null;
  }

  // Xác thực email bằng token
  async verifyEmail(token: string): Promise<{ message: string }> {
    const user = await this.userService.findByEmailVerificationToken(token);
    if (
      !user ||
      (user.emailVerificationExpires &&
        user.emailVerificationExpires < new Date())
    ) {
      throw new BadRequestException(
        'Token xác thực không hợp lệ hoặc đã hết hạn',
      );
    }

    await this.userService.update(user.id, {
      emailVerified: true,
      emailVerificationToken: undefined,
      emailVerificationExpires: undefined,
    });

    return { message: 'Email đã được xác thực thành công' };
  }

  // Gửi lại email xác thực
  async resendVerificationEmail(email: string): Promise<{ message: string }> {
    const user = await this.userService.findByEmail(email);
    if (!user) {
      throw new BadRequestException('Không tìm thấy tài khoản với email này');
    }

    if (user.emailVerified) {
      throw new BadRequestException('Email đã được xác thực');
    }

    const emailVerificationToken = randomBytes(32).toString('hex');
    const emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // Hết hạn sau 24 giờ

    await this.userService.update(user.id, {
      emailVerificationToken,
      emailVerificationExpires,
    });

    void this.mailService.sendVerificationEmail(user.email, emailVerificationToken);

    return { message: 'Email xác thực đã được gửi lại' };
  }

  // Quên mật khẩu
  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
  ): Promise<{ message: string }> {
    const { email } = forgotPasswordDto;
    const user = await this.userService.findByEmail(email);

    if (!user || user.provider !== AuthProvider.LOCAL) {
      // Không tiết lộ email có tồn tại hay không
      return { message: 'Nếu email tồn tại, link reset mật khẩu đã được gửi' };
    }

    const resetToken = randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 10 * 60 * 1000); // Hết hạn sau 10 phút

    await this.userService.update(user.id, {
      passwordResetToken: resetToken,
      passwordResetExpires: resetExpires,
    });

    void this.mailService.sendPasswordResetEmail(user.email, resetToken);

    return { message: 'Nếu email tồn tại, link reset mật khẩu đã được gửi' };
  }

  // Reset mật khẩu
  async resetPassword(
    resetPasswordDto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    const { token, newPassword } = resetPasswordDto;
    const user = await this.userService.findByPasswordResetToken(token);
    if (
      !user ||
      (user.passwordResetExpires && user.passwordResetExpires < new Date())
    ) {
      throw new BadRequestException('Token reset không hợp lệ hoặc đã hết hạn');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12); 

    await this.userService.update(user.id, {
      password: hashedPassword,
      passwordResetToken: undefined,
      passwordResetExpires: undefined,
    });

    return { message: 'Mật khẩu đã được reset thành công' };
  }

  // Thay đổi mật khẩu
  async changePassword(
    userId: number,
    changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    const { oldPassword, newPassword } = changePasswordDto;

    const user = await this.userService.findById(userId);
    if (!user) {
      throw new UnauthorizedException('Không tìm thấy người dùng');
    }

    if (user.provider !== AuthProvider.LOCAL || !user.password) {
      throw new BadRequestException(
        'Không thể thay đổi mật khẩu cho tài khoản này',
      );
    }

    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordValid) {
      throw new BadRequestException('Mật khẩu cũ không đúng');
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 12);

    await this.userService.update(userId, {
      password: hashedNewPassword,
    });

    return { message: 'Mật khẩu đã được thay đổi thành công' };
  }

  // Xác thực Google user
  async validateGGUser(ggUser: GGUser): Promise<Users> {
    let user = await this.userService.findByEmail(ggUser.email);

    if (user) {
      // Cập nhật thông tin user hiện có
      user = await this.userService.update(user.id, {
        fullName: ggUser.fullName,
        picture: ggUser.picture,
        googleId: ggUser.googleId,
        provider: AuthProvider.GOOGLE,
        emailVerified: true, // Tài khoản Google tự động xác thực
      });
    } else {
      // Tạo user mới
      user = await this.userService.create({
        email: ggUser.email,
        username: ggUser.email.split('@')[0], // Generate username from email
        fullName: ggUser.fullName,
        picture: ggUser.picture,
        googleId: ggUser.googleId,
        provider: AuthProvider.GOOGLE,
        emailVerified: true,
      });
    }

    if (!user) {
      throw new BadRequestException(
        'Không thể tạo hoặc cập nhật tài khoản Google',
      );
    }

    return user;
  }

  // Tạo JWT token và trả về thông tin user
  private generateTokenResponse(
    user: Users,
  ): { access_token: string; user: Partial<Users> } {
    if (!user.id || !user.email) {
      throw new BadRequestException('Thông tin user không hợp lệ');
    }

    const payload: JwtPayload = {
      sub: user.id.toString(),
      email: user.email,
      fullName: user.fullName || '',
    };

    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        fullName: user.fullName,

      },
    };
  }


}
