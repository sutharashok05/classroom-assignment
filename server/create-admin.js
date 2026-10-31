
import 'dotenv/config';
import mongoose from 'mongoose';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

import User from './models/User.js';

const rl = readline.createInterface({ input, output });

async function main() {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is missing from server/.env');
    }

    await mongoose.connect(process.env.MONGODB_URI);

    console.log('\nConnected database:', mongoose.connection.name);

    const confirmDb = await rl.question(
      'Is this the correct application database? Type YES to continue: '
    );

    if (confirmDb.trim() !== 'YES') {
      console.log('Cancelled. No user was created.');
      return;
    }

    const name = (await rl.question('Admin name: ')).trim();
    const email = (await rl.question('Admin email: ')).trim().toLowerCase();
    const password = await rl.question('Choose admin password (min 6 characters): ');

    if (!name || !email || password.length < 6) {
      throw new Error('Name, valid email and a password of at least 6 characters are required.');
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      console.log('This email already exists. No account was created.');
      return;
    }

    // The User model's pre-save hook hashes passwordHash with bcrypt.
    const admin = new User({
      name,
      email,
      passwordHash: password,
      role: 'admin',
      isActive: true
    });

    await admin.save();

    console.log('\nAdmin created successfully!');
    console.log('Email:', admin.email);
    console.log('Role:', admin.role);
    console.log('You can now try logging in.');
  } catch (error) {
    console.error('Admin creation failed:', error.message);
  } finally {
    rl.close();
    await mongoose.disconnect().catch(() => {});
  }
}

main();
