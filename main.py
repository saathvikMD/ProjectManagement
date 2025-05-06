import streamlit as st
import bcrypt
import json
import os

# === Helper Functions ===

def load_data():
    # Load user data
    if os.path.exists("users.json") and os.path.getsize("users.json") > 0:
        with open("users.json", "r") as f:
            user_db = json.load(f)
    else:
        user_db = {}

    # Load project data
    if os.path.exists("projects.json") and os.path.getsize("projects.json") > 0:
        with open("projects.json", "r") as f:
            project_data = json.load(f)
    else:
        project_data = {
            "projects_created": {},
            "projects_joined": {}
        }

    return user_db, project_data

def save_data(user_db, project_data):
    with open("users.json", "w") as f:
        json.dump(user_db, f)

    with open("projects.json", "w") as f:
        json.dump(project_data, f)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

# === Main App Logic ===

user_db, project_data = load_data()
projects_created = project_data["projects_created"]
projects_joined = project_data["projects_joined"]
all_projects = set(p for plist in projects_created.values() for p in plist)

def check_credentials(username, password):
    if username in user_db:
        return check_password(password, user_db[username])
    return False

def login():
    if not st.session_state.get("logged_in"):
        st.title("Login")

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if check_credentials(username, password):
                st.session_state.logged_in = True
                st.session_state.username = username
                st.success(f"Welcome, {username}!")
                st.rerun()
            else:
                st.error("Invalid username or password")

        if st.checkbox("Create New Account"):
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            if st.button("Register"):
                if new_username in user_db:
                    st.warning("Username already exists.")
                else:
                    user_db[new_username] = hash_password(new_password)
                    save_data(user_db, project_data)
                    st.success("Account created! Please log in.")
    else:
        dashboard()

def dashboard():
    username = st.session_state.username
    st.title(f"Welcome Back, {username} 👋")

    # Ensure project_details exists
    if "project_details" not in project_data:
        project_data["project_details"] = {}

    tab1, tab2, tab3 = st.tabs(["Dashboard", "Join/Create Project", "Project Workspace"])

    with tab1:
        st.subheader("Your Projects")
        if st.button("🔄 Refresh Dashboard"):
            st.rerun()

        created = projects_created.get(username, [])
        if created:
            for p in created:
                st.markdown(f"- **{p}**")
        else:
            st.info("You haven't created any projects yet.")

        st.subheader("Projects Joined")
        joined = projects_joined.get(username, [])
        if joined:
            for p in joined:
                st.markdown(f"- {p}")
        else:
            st.info("You haven't joined any projects yet.")

    with tab2:
        st.subheader("Create a New Project")
        new_project = st.text_input("Project Name")
        if st.button("Create Project"):
            if new_project:
                if new_project not in all_projects:
                    projects_created.setdefault(username, []).append(new_project)
                    all_projects.add(new_project)
                    # Initialize project_details
                    project_data.setdefault("project_details", {})[new_project] = {
                        "leader": username,
                        "members": [username],
                        "chat": []
                    }
                    save_data(user_db, project_data)
                    st.success(f"Project '{new_project}' created!")
                else:
                    st.warning("Project already exists.")
            else:
                st.warning("Enter a project name.")

        st.markdown("---")
        st.subheader("Join an Existing Project")
        available = list(all_projects - set(projects_created.get(username, [])) - set(projects_joined.get(username, [])))
        if available:
            selected = st.selectbox("Select a project to join", available)
            if st.button("Join Project"):
                projects_joined.setdefault(username, []).append(selected)
                # Add to project_details
                project_data.setdefault("project_details", {}).setdefault(selected, {
                    "leader": None,
                    "members": [],
                    "chat": []
                })
                if username not in project_data["project_details"][selected]["members"]:
                    project_data["project_details"][selected]["members"].append(username)
                save_data(user_db, project_data)
                st.success(f"Joined project '{selected}'")
        else:
            st.info("No projects available to join.")

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    with tab3:
        st.subheader("Project Workspace")
        if st.button("🔄 Refresh Workspace"):
            st.rerun()

        # Download projects.json
        with open("projects.json", "r") as f:
            st.download_button("📁 Download Projects Data", f.read(), file_name="projects.json", mime="application/json")

        user_projects = set(projects_created.get(username, []) + projects_joined.get(username, []))
        if user_projects:
            selected_project = st.selectbox("Select a project to open", list(user_projects))
            details = project_data.get("project_details", {}).get(selected_project, {})
            st.markdown(f"**Leader:** {details.get('leader', 'Unknown')}")
            st.markdown("**Members:**")
            for member in details.get("members", []):
                st.write(f"- {member}")

            st.markdown("---")
            st.markdown("**Project Chat**")
            for entry in details.get("chat", []):
                st.markdown(f"**{entry['user']}**: {entry['message']}")

            new_msg = st.text_input("Send a message", key="chat_input")
            if st.button("Send") and new_msg.strip():
                details["chat"].append({"user": username, "message": new_msg.strip()})
                save_data(user_db, project_data)
                st.rerun()

            # If current user is the leader, show delete button
            if username == details.get("leader"):
                if st.button("🗑️ Delete Project"):
                    # Remove from project_details
                    project_data["project_details"].pop(selected_project, None)
                    # Remove from projects_created
                    for user, plist in projects_created.items():
                        if selected_project in plist:
                            plist.remove(selected_project)
                    # Remove from projects_joined
                    for user, plist in projects_joined.items():
                        if selected_project in plist:
                            plist.remove(selected_project)
                    all_projects.discard(selected_project)
                    save_data(user_db, project_data)
                    st.success(f"Project '{selected_project}' deleted.")
                    st.rerun()
        else:
            st.info("You haven't joined or created any projects.")

def main():
    login()

if __name__ == "__main__":
    main()
