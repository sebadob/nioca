<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import X509Contents from "../../x509/X509Contents.svelte";
    import Textarea from "$lib/inputs/Textarea.svelte";
    import Button from "$lib/Button.svelte";
    import {fetchDeleteCAX509} from "../../../utils/dataFetching.js";

    export let ca = {};
    export let groups = [];
    export let onSave = () => {
    };

    let err = '';
    let show;
    let confirmDelete = false;

    $: usedInGroups = groups.filter(g => g.caX509 === ca.intermediate.id).map(g => g.name).join(', ');

    async function deleteCA() {
        let res = await fetchDeleteCAX509(ca.intermediate.id);
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
            {ca.root.id}
        </div>

        <div class="data">
            {ca.root.name}
        </div>
    </div>

    <div slot="body">
        <div class="cert">
            <div class="certHeader">
                <b>Intermediate</b>
            </div>
            <X509Contents cert={ca.intermediate}/>
            <Textarea
                    rows=14
                    name="intermediatePem"
                    disabled
                    bind:value={ca.intermediatePem}
            >
            </Textarea>
        </div>
        <div class="cert">
            <div class="certHeader">
                <b>Root</b>
            </div>
            <X509Contents cert={ca.root}/>
            <Textarea
                    rows=14
                    name="intermediatePem"
                    disabled
                    bind:value={ca.rootPem}
            >
            </Textarea>
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
        margin-left: .75rem;
    }

    .cert {
        margin: 10px;
        max-width: 32rem;
    }

    .certHeader {
        margin-left: .5rem;
        font-size: 1.1rem;
    }

    .data {
        display: flex;
        align-items: center;
        margin: 3px 10px;
    }

    .err {
        color: var(--col-err);
    }

    .header {
        display: flex;
        align-items: center;
    }
</style>
