import { IsString, MinLength, MaxLength, Matches } from 'class-validator';

export class ResetPasswordDto {
    @IsString({message: 'Token not valid' })
    token: string;

    @IsString({message: 'new password is string' })
    @MinLength(8, { message: 'new password must be at least 8 characters long' })
    @MaxLength(20, { message: 'new password must not exceed 20 characters' })
    @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,20}$/, {
        message: 'new password must contain at least one uppercase letter, one lowercase letter, and one number',
    })
    newPassword: string;
}