<script>
  import IconCheck from "./icons/IconCheck.svelte";
  import IconStop from "./icons/IconStop.svelte";
  export let check = false;
</script>

{#if check}
  <IconCheck />
{:else}
  <IconStop />
{/if}
