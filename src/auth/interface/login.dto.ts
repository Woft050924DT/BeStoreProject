import {IsEmail, IsString, MinLength} from 'class-validator';

export class LoginDto{
    @IsEmail ({},{message: 'Invalid email format'})
    email: string;

    @IsString({message: 'Password must be a string'})
    @MinLength(1, {message: 'Password must not be empty'})
    password: string;


}