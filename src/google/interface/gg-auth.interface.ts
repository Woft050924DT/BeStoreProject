import {Users} from '../../user/user.entity'
export interface GGUser{
    email: string;
    fullName: string; 
    picture: string;
    googleId: string;
    accessToken: string; 
}
export interface JwtPayload {
    sub: string;
    email:string; 
    fullName?: string;
    iat?: number;
    exp?: number;
}

export interface AuthResponse {
    success: boolean;
    token: string;
    user?: Partial<Users>;
    message?: string;

}