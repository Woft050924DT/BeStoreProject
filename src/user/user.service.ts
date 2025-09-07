import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Users } from './user.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(Users)
    private readonly userRepository: Repository<Users>,
  ) {}

  async createUser(email: string, password: string): Promise<Users> {
    const user = this.userRepository.create({ email, password });
    return this.userRepository.save(user);
  }

  async getAllUser(): Promise<Users[]> {
    return this.userRepository.find();
  }
  async findById(id: number): Promise<Users | null> {
    return this.userRepository.findOne({ where: { id } });
  }
  async findByEmail(email: string): Promise<Users | null> {
    return this.userRepository.findOne({ where: { email } });
  }
  async findByUsername(username: string): Promise<Users | null> {
    return this.userRepository.findOne({ where: { username } });
  }

  async create(userData: Partial<Users>): Promise<Users> {
    const user = this.userRepository.create(userData);
    return this.userRepository.save(user);
  }

  async update(id: number, userData: Partial<Users>): Promise<Users | null> {
    await this.userRepository.update(id, userData);
    return this.findById(id);
  }


}
