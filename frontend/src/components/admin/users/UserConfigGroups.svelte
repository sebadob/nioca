<script>
    import IconPlus from "$lib/icons/IconPlus.svelte";

    export let user;
    export let groups = [];
    export let accessGroups = [];
    export let selected;
    let search = '';

</script>

<div class="container">
    <div class="bar">
        <div
                role="button"
                tabindex="0"
                class="add"
                on:click={() => selected = '_new_'}
                on:keypress={() => selected = '_new_'}
        >
            <IconPlus color="var(--col-act2)"/>
        </div>

        <input
                type="search"
                class="search"
                bind:value={search}
        />
    </div>

    <div class="list">
        {#each accessGroups as access (access.groupId)}
            <div
                    role="button"
                    tabindex="0"
                    class="entry"
                    style:background={selected === access.groupId ? 'var(--col-gmid)' : ''}
                    on:click={() => selected = access.groupId}
                    on:keypress={() => selected = access.groupId}
            >
                {groups.filter(g => g.id === access.groupId)[0].name}
            </div>
        {/each}
    </div>
</div>

<style>
    .add {
        margin-bottom: -.25rem;
        cursor: pointer;
    }

    .bar {
        padding-left: .5rem;
        display: flex;
        align-items: center;
        gap: .5rem;
    }

    .container {
        padding: .5rem 0 .5rem .5rem;
    }

    .entry {
        padding: 0 .5rem;
        cursor: pointer;
    }

    .entry:hover {
        background: var(--col-gmid);
    }

    .list {
        margin-top: .75rem;
        display: flex;
        flex-direction: column;
    }

    .search {
        margin-right: .5rem;
        width: 12rem;
    }
</style>
