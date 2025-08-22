import { Entity, PrimaryColumn, Column } from 'typeorm';

@Entity('users')
export class Users {
  @PrimaryColumn('uuid')
  id: string;

  @Column()
  email: string;

  @Column({ name: 'password' })
  password: string;

  @Column({ name: 'full_name', nullable: true })
  fullName: string;

  @Column ({ name: 'first_name', nullable: true})
  firstName?: string;

  @Column({ name: 'last_name',nullable: true })
  lastName?: string;

  @Column({ name: 'picture', nullable: true })
  picture: string; 
  
  @Column({ name: 'googleid',nullable: true })
  googleId: string;

  @Column({ name:'provider',nullable: true })
  provider: string;

  @Column({ name:'phone',nullable: true })
  phone: string;

  @Column({ name:'phone',nullable: true })
  role: string;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @Column({ name: 'created_at', type: 'timestamp', nullable: true })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'timestamp', nullable: true })
  updatedAt: Date;

  @Column({ name: 'deleted_at', type: 'timestamp', nullable: true })
  deletedAt: Date | null;
}