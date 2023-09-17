<script>
    import CaSshTile from "./CaSshTile.svelte";
    import CaSshAddNew from "./CaSshAddNew.svelte";

    export let cas = [];
    export let groups = [];
    export let onSave = () => {
    };

    // const searchOptions = [
    //     {label: 'ID', accessor: 'certId'},
    //     {label: 'Group', accessor: 'groupName'},
    // ];

</script>

<div class="container">
    <CaSshAddNew onSave={onSave}/>

    {#each cas as ca (ca.id)}
        <CaSshTile bind:ca bind:groups onSave={onSave}/>
    {/each}
</div>

<style>
    .container {
        display: flex;
        flex-direction: column;
    }
</style>
