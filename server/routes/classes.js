
import express from 'express';
import { param } from 'express-validator';

import { hybridAuthMiddleware } from '../middleware/hybridAuth.js';

import {
  createClass,
  getTeacherClasses,
  getStudentClasses,
  getClass,
  joinClass,
  updateClass,
  deleteClass,
  removeStudent,
  getClassStats
} from '../controllers/classController.js';

import {
  createClassValidation,
  joinClassValidation,
  classIdValidation
} from '../middleware/validation.js';

const router = express.Router();

// All class routes require valid session or JWT authentication.
// hybridAuthMiddleware must set req.user before the route handlers run.
router.use(hybridAuthMiddleware);

// Helper middleware: allow only teachers and admins.
const requireTeacher = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. Please log in.'
    });
  }

  if (req.user.role !== 'teacher' && req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Only teachers can perform this action.'
    });
  }

  next();
};

// Helper middleware: allow only students.
const requireStudent = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. Please log in.'
    });
  }

  if (req.user.role !== 'student') {
    return res.status(403).json({
      success: false,
      message: 'Only students can perform this action.'
    });
  }

  next();
};

// Create a new class (teachers and admins only).
router.post(
  '/',
  requireTeacher,
  createClassValidation,
  createClass
);

// Get classes for the currently authenticated user.
router.get('/my-classes', (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. Please log in.'
    });
  }

  const role = req.user.role;

  if (role === 'teacher' || role === 'admin') {
    return getTeacherClasses(req, res, next);
  }

  if (role === 'student') {
    return getStudentClasses(req, res, next);
  }

  return res.status(403).json({
    success: false,
    message: 'You do not have permission to access these classes.'
  });
});

// Join a class using a join code (students only).
router.post(
  '/join',
  requireStudent,
  joinClassValidation,
  joinClass
);

// Get a specific class.
router.get(
  '/:classId',
  classIdValidation,
  getClass
);

// Update a class (teachers and admins only).
router.patch(
  '/:classId',
  requireTeacher,
  classIdValidation,
  createClassValidation,
  updateClass
);

// Delete a class (teachers and admins only).
router.delete(
  '/:classId',
  requireTeacher,
  classIdValidation,
  deleteClass
);

// Remove a student from a class (teachers and admins only).
router.delete(
  '/:classId/students/:studentId',
  requireTeacher,
  classIdValidation,
  param('studentId')
    .isMongoId()
    .withMessage('Invalid student ID'),
  removeStudent
);

// Get class statistics.
router.get(
  '/:classId/stats',
  classIdValidation,
  getClassStats
);

export default router;
