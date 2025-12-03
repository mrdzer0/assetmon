#!/usr/bin/env python3
"""
User Management CLI Script
Manage users for Asset Monitor authentication

Usage:
    python3 manage_users.py create <username> [--email EMAIL] [--full-name NAME] [--superuser]
    python3 manage_users.py list
    python3 manage_users.py delete <username>
    python3 manage_users.py reset-password <username>
    python3 manage_users.py activate <username>
    python3 manage_users.py deactivate <username>
"""

import sys
import os
import getpass
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.db import SessionLocal
from app.models import User
from app.auth import hash_password


def create_user(username: str, email: str = None, full_name: str = None, is_superuser: bool = False):
    """Create a new user"""
    db = SessionLocal()

    try:
        # Check if user already exists
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            print(f"❌ Error: User '{username}' already exists")
            return False

        # Get password
        print(f"\n🔐 Creating user: {username}")
        password = getpass.getpass("Enter password: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("❌ Error: Passwords do not match")
            return False

        if len(password) < 8:
            print("❌ Error: Password must be at least 8 characters")
            return False

        # Create user
        user = User(
            username=username,
            email=email,
            full_name=full_name,
            hashed_password=hash_password(password),
            is_active=True,
            is_superuser=is_superuser,
            created_at=datetime.utcnow(),
            password_changed_at=datetime.utcnow()
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        print(f"\n✅ User created successfully!")
        print(f"   Username: {user.username}")
        if user.email:
            print(f"   Email: {user.email}")
        if user.full_name:
            print(f"   Full Name: {user.full_name}")
        print(f"   Superuser: {'Yes' if user.is_superuser else 'No'}")
        print(f"   Created: {user.created_at}")

        return True

    except Exception as e:
        print(f"❌ Error creating user: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def list_users():
    """List all users"""
    db = SessionLocal()

    try:
        users = db.query(User).order_by(User.created_at.desc()).all()

        if not users:
            print("📋 No users found")
            return

        print(f"\n📋 Users ({len(users)}):")
        print("=" * 100)
        print(f"{'ID':<5} {'Username':<20} {'Email':<30} {'Active':<8} {'Superuser':<10} {'Last Login':<20}")
        print("=" * 100)

        for user in users:
            last_login = user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never'
            active_status = '✅ Yes' if user.is_active else '❌ No'
            super_status = '👑 Yes' if user.is_superuser else 'No'

            print(f"{user.id:<5} {user.username:<20} {user.email or '-':<30} {active_status:<8} {super_status:<10} {last_login:<20}")

        print("=" * 100)

    except Exception as e:
        print(f"❌ Error listing users: {e}")
    finally:
        db.close()


def delete_user(username: str):
    """Delete a user"""
    db = SessionLocal()

    try:
        user = db.query(User).filter(User.username == username).first()

        if not user:
            print(f"❌ Error: User '{username}' not found")
            return False

        # Confirm deletion
        confirm = input(f"\n⚠️  Are you sure you want to delete user '{username}'? (yes/no): ")
        if confirm.lower() != 'yes':
            print("❌ Deletion cancelled")
            return False

        db.delete(user)
        db.commit()

        print(f"✅ User '{username}' deleted successfully")
        return True

    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def reset_password(username: str):
    """Reset user password"""
    db = SessionLocal()

    try:
        user = db.query(User).filter(User.username == username).first()

        if not user:
            print(f"❌ Error: User '{username}' not found")
            return False

        # Get new password
        print(f"\n🔐 Resetting password for: {username}")
        password = getpass.getpass("Enter new password: ")
        password_confirm = getpass.getpass("Confirm new password: ")

        if password != password_confirm:
            print("❌ Error: Passwords do not match")
            return False

        if len(password) < 8:
            print("❌ Error: Password must be at least 8 characters")
            return False

        # Update password
        user.hashed_password = hash_password(password)
        user.password_changed_at = datetime.utcnow()
        db.commit()

        print(f"✅ Password reset successfully for '{username}'")
        return True

    except Exception as e:
        print(f"❌ Error resetting password: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def activate_user(username: str):
    """Activate a user"""
    db = SessionLocal()

    try:
        user = db.query(User).filter(User.username == username).first()

        if not user:
            print(f"❌ Error: User '{username}' not found")
            return False

        if user.is_active:
            print(f"ℹ️  User '{username}' is already active")
            return True

        user.is_active = True
        db.commit()

        print(f"✅ User '{username}' activated successfully")
        return True

    except Exception as e:
        print(f"❌ Error activating user: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def deactivate_user(username: str):
    """Deactivate a user"""
    db = SessionLocal()

    try:
        user = db.query(User).filter(User.username == username).first()

        if not user:
            print(f"❌ Error: User '{username}' not found")
            return False

        if not user.is_active:
            print(f"ℹ️  User '{username}' is already inactive")
            return True

        # Confirm deactivation
        confirm = input(f"\n⚠️  Are you sure you want to deactivate user '{username}'? (yes/no): ")
        if confirm.lower() != 'yes':
            print("❌ Deactivation cancelled")
            return False

        user.is_active = False
        db.commit()

        print(f"✅ User '{username}' deactivated successfully")
        return True

    except Exception as e:
        print(f"❌ Error deactivating user: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def print_usage():
    """Print usage information"""
    print("""
🔧 Asset Monitor - User Management CLI

Usage:
    python3 manage_users.py create <username> [options]
    python3 manage_users.py list
    python3 manage_users.py delete <username>
    python3 manage_users.py reset-password <username>
    python3 manage_users.py activate <username>
    python3 manage_users.py deactivate <username>

Commands:
    create              Create a new user
    list                List all users
    delete              Delete a user
    reset-password      Reset user password
    activate            Activate a user account
    deactivate          Deactivate a user account

Options for create:
    --email EMAIL       User email address
    --full-name NAME    User full name
    --superuser         Make user a superuser (admin)

Examples:
    # Create a regular user
    python3 manage_users.py create john --email john@example.com --full-name "John Doe"

    # Create a superuser
    python3 manage_users.py create admin --superuser

    # List all users
    python3 manage_users.py list

    # Reset password
    python3 manage_users.py reset-password john

    # Delete a user
    python3 manage_users.py delete john
    """)


def main():
    """Main CLI entry point"""
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "create":
        if len(sys.argv) < 3:
            print("❌ Error: Username required")
            print("Usage: python3 manage_users.py create <username> [options]")
            sys.exit(1)

        username = sys.argv[2]
        email = None
        full_name = None
        is_superuser = False

        # Parse options
        i = 3
        while i < len(sys.argv):
            arg = sys.argv[i]
            if arg == "--email" and i + 1 < len(sys.argv):
                email = sys.argv[i + 1]
                i += 2
            elif arg == "--full-name" and i + 1 < len(sys.argv):
                full_name = sys.argv[i + 1]
                i += 2
            elif arg == "--superuser":
                is_superuser = True
                i += 1
            else:
                print(f"❌ Error: Unknown option '{arg}'")
                sys.exit(1)

        success = create_user(username, email, full_name, is_superuser)
        sys.exit(0 if success else 1)

    elif command == "list":
        list_users()
        sys.exit(0)

    elif command == "delete":
        if len(sys.argv) < 3:
            print("❌ Error: Username required")
            print("Usage: python3 manage_users.py delete <username>")
            sys.exit(1)

        username = sys.argv[2]
        success = delete_user(username)
        sys.exit(0 if success else 1)

    elif command == "reset-password":
        if len(sys.argv) < 3:
            print("❌ Error: Username required")
            print("Usage: python3 manage_users.py reset-password <username>")
            sys.exit(1)

        username = sys.argv[2]
        success = reset_password(username)
        sys.exit(0 if success else 1)

    elif command == "activate":
        if len(sys.argv) < 3:
            print("❌ Error: Username required")
            print("Usage: python3 manage_users.py activate <username>")
            sys.exit(1)

        username = sys.argv[2]
        success = activate_user(username)
        sys.exit(0 if success else 1)

    elif command == "deactivate":
        if len(sys.argv) < 3:
            print("❌ Error: Username required")
            print("Usage: python3 manage_users.py deactivate <username>")
            sys.exit(1)

        username = sys.argv[2]
        success = deactivate_user(username)
        sys.exit(0 if success else 1)

    else:
        print(f"❌ Error: Unknown command '{command}'")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
