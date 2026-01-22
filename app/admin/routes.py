"""
Admin routes for the Flask Auth Skeleton application.

This module provides routes for:
- Viewing all users
- Editing user roles
- Deleting users

Requirements addressed:
- 6.1: Admin_Panel SHALL display a list of all users with their roles
- 6.2: Admin changes a user's role
- 6.3: Admin deletes a user
- 6.4: Prevent admin self-deletion
- 6.5: Display email, role, and registration date for each user
- 10.4: THE System SHALL sanitize all user inputs to prevent injection attacks
"""

from flask import render_template, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from app.admin import admin_bp
from app.admin.forms import EditUserRoleForm
from app.auth.decorators import admin_required
from app.services.user_service import UserService
from app.utils.sanitization import sanitize_role


@admin_bp.route('/users')
@login_required
@admin_required
def list_users():
    """
    Display list of all users with their email, role, and registration date.
    
    This route retrieves all users from the database using UserService
    and displays them in a table format with edit and delete action buttons.
    
    Requirements:
        - 6.1: Display a list of all users with their roles
        - 6.5: Display email, role, and registration date for each user
    
    Returns:
        Rendered admin/users.html template with list of all users.
    """
    users = UserService.get_all_users()
    return render_template('admin/users.html', users=users)


@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id: int):
    """
    Edit user role.
    
    This route allows admins to change a user's role between 'admin' and 'user'.
    On GET, it displays a form with the current role selected.
    On POST, it validates and sanitizes the input, then updates the role.
    
    Args:
        user_id: ID of the user to edit
    
    Requirements:
        - 6.2: WHEN an Admin changes a user's role, THE User_Repository SHALL 
               update the role and persist the change
        - 10.4: THE System SHALL sanitize all user inputs to prevent injection attacks
    
    Returns:
        GET: Rendered edit_user.html template with user data
        POST: Redirect to user list with success/error flash message
    
    Raises:
        404: If user with given ID is not found
    """
    # Get the user or return 404 if not found
    user = UserService.get_user_by_id(user_id)
    if user is None:
        abort(404)
    
    # Create form and set current role as default
    form = EditUserRoleForm()
    
    if form.validate_on_submit():
        # Get and sanitize the new role from the form (Requirement 10.4)
        new_role = sanitize_role(form.role.data)
        
        # Validate the sanitized role
        if new_role is None:
            flash('Invalid role selected. Please choose either Admin or User.', 'error')
            return render_template('admin/edit_user.html', user=user, form=form)
        
        # Update the user's role
        try:
            success = UserService.update_user_role(user_id, new_role)
            if success:
                flash(f'Successfully updated role for {user.email} to {new_role}.', 'success')
            else:
                flash('Failed to update user role. Please try again.', 'error')
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('admin/edit_user.html', user=user, form=form)
        
        return redirect(url_for('admin.list_users'))
    
    # For GET request, pre-select the current role
    if not form.is_submitted():
        form.role.data = user.role
    
    # GET request or validation failed - display the edit form
    return render_template('admin/edit_user.html', user=user, form=form)


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id: int):
    """
    Delete a user from the database.
    
    This route allows admins to delete users from the system. It prevents
    admins from deleting their own account to ensure there's always at least
    one admin who can manage the system.
    
    Args:
        user_id: ID of the user to delete
    
    Requirements:
        - 6.3: WHEN an Admin deletes a user, THE User_Repository SHALL remove 
               the user from the database
        - 6.4: WHEN an Admin attempts to delete their own account, THE System 
               SHALL prevent the deletion and display an error
    
    Returns:
        Redirect to user list with success/error flash message
    
    Raises:
        404: If user with given ID is not found
    """
    # Prevent self-deletion (Requirement 6.4)
    if user_id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin.list_users'))
    
    # Get the user or return 404 if not found
    user = UserService.get_user_by_id(user_id)
    if user is None:
        abort(404)
    
    # Store email for the success message before deletion
    user_email = user.email
    
    # Delete the user (Requirement 6.3)
    success = UserService.delete_user(user_id)
    
    if success:
        flash(f'Successfully deleted user {user_email}.', 'success')
    else:
        flash('Failed to delete user. Please try again.', 'error')
    
    return redirect(url_for('admin.list_users'))
