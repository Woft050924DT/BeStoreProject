import {Users} from '../../user/user.entity'
export interface GGUser{
    email: string;
    firstName: string; 
    lastName: string;
    picture: string;
    googleId: string;
    accessToken: string; 
}
export interface JwtPayload {
    sub: string;
    email:string; 
    firstName?: string;
    lastName?: string;
    iat?: number;
    exp?: number;
}

export interface AuthResponse {
    success: boolean;
    token: string;
    user?: Partial<Users>;
    message?: string;

}