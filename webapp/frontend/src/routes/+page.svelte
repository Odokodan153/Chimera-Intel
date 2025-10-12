<script>
  import { onMount } from 'svelte';

  let projects = [];
  let currentUser = null;

  onMount(async () => {
    // In a real application, you would fetch this data from your API
    currentUser = { name: 'Admin' };
    projects = [
      { id: 1, name: 'Project Alpha', status: 'In Progress' },
      { id: 2, name: 'Project Beta', status: 'Completed' },
    ];
  });
</script>

<div class="container">
  <h1>Welcome to Chimera Intel, {currentUser?.name}</h1>

  <div class="project-list">
    <h2>Your Projects</h2>
    {#each projects as project}
      <div class="project-card">
        <h3>{project.name}</h3>
        <p>Status: {project.status}</p>
        <a href="/projects/{project.id}">View Details</a>
      </div>
    {/each}
  </div>
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
</style>