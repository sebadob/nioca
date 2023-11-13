<script>
    import UserConfigGroups from "./UserConfigGroups.svelte";
    import UserConfigContent from "./UserConfigContent.svelte";

    export let user;
    export let groups = [];
    export let accessGroups = [];
    export let onSave = () => {
    };

    let selected = '';

    $: accessSet = new Set(accessGroups.map(ag => ag.groupId));
    $: groupsFiltered = groups.filter(g => !accessSet.has(g.id));
    $: accessGroupSelected = selected !== '' && selected !== '_new_'
        ? accessGroups.filter(ag => ag.groupId === selected)[0]
        : undefined;

</script>

<div class="container">
    <UserConfigGroups
            bind:user
            bind:groups
            bind:accessGroups
            bind:selected
    />
    <UserConfigContent
            bind:user
            groupsFiltered={groupsFiltered}
            bind:selected
            bind:accessGroupSelected
            onSave={onSave}
    />
</div>

<style>
    .container {
        display: flex;
    }
</style>
