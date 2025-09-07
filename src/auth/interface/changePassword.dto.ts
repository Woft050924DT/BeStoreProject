import { IsString, MinLength, MaxLength, Matches } from 'class-validator';

export class ChangePasswordDto{
    @IsString({message: 'Old password must be a string'})
    oldPassword: string;

    @IsString({message: 'New password must be a string'})
    @MinLength(8, {message: 'New password must be at least 8 characters long'})
    @MaxLength(20, {message: 'New password must not exceed 20 characters'})
    @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/, {
        message: 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    })
    newPassword: string;
}