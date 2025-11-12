<script>
  import { onMount } from 'svelte';

  let projects = [];
  let currentUser = null;
  let error = null;

  onMount(async () => {
    // This now fetches live data from your "real" API endpoints
    try {
      // 1. Fetch the current user
      const userRes = await fetch('/api/users/me'); // Calls auth.py
      if (!userRes.ok) {
        if (userRes.status === 401) {
          throw new Error('You are not logged in. Please log in to continue.');
        }
        throw new Error(`Failed to fetch user: ${userRes.statusText}`);
      }
      currentUser = await userRes.json();

      // 2. Fetch the projects for that user
      const projectsRes = await fetch('/api/projects'); // Calls the_eye_api.py
       if (!projectsRes.ok) {
        throw new Error(`Failed to fetch projects: ${projectsRes.statusText}`);
      }
      projects = await projectsRes.json();

    } catch (e) {
      console.error(e);
      error = e.message;
    }
  });
</script>

<div class="container">
  {#if error}
    <div class="error-box">
      <h2>Error loading dashboard</h2>
      <p>{error}</p>
      {#if error.includes('log in')}
        <a href="/login.html">Go to Login</a>
      {/if}
    </div>
  {:else if currentUser}
    <h1>Welcome to Chimera Intel, {currentUser.username || 'Analyst'}</h1>

    <div class="project-list">
      <h2>Your Projects</h2>
      {#if projects.length === 0}
        <p>You have no projects. Create one using the CLI to begin.</p>
      {:else}
        {#each projects as project}
          <div class="project-card">
            <h3>{project.name}</h3>
            <p>Description: {project.description || 'N/A'}</p>
            
            <a href="/project/{project.name}">View Details</a>
          </div>
        {/each}
      {/if}
    </div>
  {:else}
     <p>Loading dashboard...</p>
  {/if}
</div>

<style>
  .container {
    padding: 2rem;
    font-family: Arial, sans-serif;
  }
  .project-list {
    margin-top: 2rem;
  }
  .project-card {
    border: 1px solid #ccc;
    padding: 1rem;
    margin-bottom: 1rem;
    border-radius: 8px;
  }
  .error-box {
    background-color: #ffe8e8;
    border: 1px solid #e74c3c;
    color: #c0392b;
    padding: 1rem;
    border-radius: 8px;
  }
  .error-box a {
    display: inline-block;
    margin-top: 1rem;
    padding: 0.5rem 1rem;
    background-color: #c0392b;
    color: white;
    text-decoration: none;
    border-radius: 4px;
  }
</style>