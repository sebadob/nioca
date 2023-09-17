<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import Button from "$lib/Button.svelte";
    import {fetchDeleteCAXSsh} from "../../../utils/dataFetching.js";

    export let ca = {};
    export let groups = [];
    export let onSave = () => {
    };

    let err = '';
    let show;
    let confirmDelete = false;

    $: usedInGroups = groups.filter(g => g.caSsh === ca.id).map(g => g.name).join(', ');

    async function deleteCA() {
        let res = await fetchDeleteCAXSsh(ca.id);
        if (res.ok) {
            onSave();
        } else {
            let body = await res.json();
            err = body.message;
        }
    }

</script>

<ExpandContainer bind:show>
    <div class="header" slot="header">
        <div class="data font-mono">
            {ca.id}
        </div>

        <div class="data">
            {ca.name}
        </div>
    </div>

    <div slot="body">
        <div class="data">
            <div class="font-label label">
                <b>PUBLIC KEY</b>
            </div>
            <div class="font-mono">
                <code>
                    {ca.pubKey}
                </code>
            </div>
        </div>

        <div class="bottom">
            {#if usedInGroups && usedInGroups.length > 0}
                The following groups are using this CA: <br/>
                {usedInGroups}
            {:else if confirmDelete}
                Are you really sure, that you want to delete this CA?<br>
                <Button on:click={deleteCA} level={1}>DELETE</Button>
                <Button on:click={() => confirmDelete = false} level={3}>CANCEL</Button>
            {:else}
                This CA is unused. It is possible to delete it.<br/>
                <Button on:click={() => confirmDelete = true} level={3}>DELETE</Button>
            {/if}

            {#if err}
                <div class="err">
                    {err}
                </div>
            {/if}
        </div>
    </div>
</ExpandContainer>

<style>
    .bottom {
        margin: .75rem;
    }

    .data {
        display: flex;
        flex-direction: column;
        /*align-items: center;*/
        margin: .25rem .75rem;
    }

    .err {
        color: var(--col-err);
    }

    .header {
        display: flex;
        align-items: center;
    }

    .label {
        font-size: .85rem;
    }
</style>
