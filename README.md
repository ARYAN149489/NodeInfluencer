# Promo.com - Influencer Marketing Platform

This project is a full-stack web application that connects influencers with collaborators. It features user authentication, profile management, event posting, an influencer search engine, and an admin panel for user management.

## Features

- **User Roles**: Separate dashboards and functionalities for Influencers, Collaborators, and Admins.
- **Secure Authentication**: Passwords are securely hashed using bcrypt, and user sessions are managed on the server.
- **Profile Management**: Users can create and update detailed profiles with pictures.
- **Influencer Search**: Collaborators can search for influencers by field, city, and name.
- **Admin Panel**: Admins can view, block, resume, and delete users.

## Tech Stack

- **Backend**: Node.js, Express.js
- **Frontend**: HTML, CSS, JavaScript, Bootstrap, jQuery, AngularJS
- **Database**: MySQL
- **Security**: bcrypt, express-session
- **File Uploads**: express-fileupload
- **Emailing**: nodemailer

## Setup and Installation

### 1. Prerequisites

- Node.js installed
- MySQL Server installed and running

### 2. Clone & Install Dependencies

Clone the repository and install the required npm packages.
```bash
git clone <your-repo-url>
cd promo_com_refactored
npm install