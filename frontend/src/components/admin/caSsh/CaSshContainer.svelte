<script>
    import CaSshTile from "./CaSshTile.svelte";

    export let cas;

    const searchOptions = [
        {label: 'ID', accessor: 'certId'},
        {label: 'Group', accessor: 'groupName'},
    ];

</script>

{#each cas as ca (ca.certId)}
    <CaSshTile bind:ca/>
{/each}
