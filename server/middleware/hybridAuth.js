
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export const hybridAuthMiddleware = async (req, res, next) => {
  try {
    let user = null;
    let authMethod = 'none';

    // 1. Try session authentication first
    const sessionUserId = req.session?.userId;

    if (sessionUserId) {
      console.log('🔍 Hybrid Auth: Trying session auth');

      user = await User.findById(sessionUserId).select('-passwordHash');

      if (user?.isActive) {
        authMethod = 'session';
        console.log('✅ Hybrid Auth: Session auth successful');
      } else {
        user = null;
      }
    }

    // 2. Fall back to JWT authentication
    if (!user) {
      const authHeader = req.headers.authorization;

      if (authHeader?.startsWith('Bearer ')) {
        console.log('🔍 Hybrid Auth: Trying JWT auth');

        const token = authHeader.slice(7);

        try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET);

          if (typeof decoded === 'object' && decoded.userId) {
            user = await User.findById(decoded.userId)
              .select('-passwordHash');

            if (user?.isActive) {
              authMethod = 'jwt';
              console.log('✅ Hybrid Auth: JWT auth successful');
            } else {
              user = null;
            }
          }
        } catch (error) {
          console.log('❌ Hybrid Auth: JWT verification failed');
          user = null;
        }
      }
    }

    // 3. Reject unauthenticated requests
    if (!user) {
      console.log('❌ Hybrid Auth: No valid authentication found');

      return res.status(401).json({
        success: false,
        message: 'Access denied. Please log in.',
        authMethod: 'none'
      });
    }

    // 4. Make authenticated user available to downstream routes
    req.user = user;
    req.authMethod = authMethod;

    console.log(
      `✅ Hybrid Auth: User authenticated via ${authMethod}: ${user.name}`
    );

    return next();
  } catch (error) {
    console.error('Hybrid auth middleware error:', error.message);

    return res.status(500).json({
      success: false,
      message: 'Server error during authentication.'
    });
  }
};

export const hybridAuth = hybridAuthMiddleware;
export default hybridAuthMiddleware;
