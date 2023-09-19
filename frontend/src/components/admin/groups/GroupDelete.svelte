<script>
    import Button from "$lib/Button.svelte";
    import {fetchDeleteClientSsh, fetchDeleteGroup} from "../../../utils/dataFetching.js";

    export let group = {};
    export let onSave;

    // let isLoading = false;
    let err = '';

    // let success = false;

    async function onSubmit() {
        err = '';

        let res = await fetchDeleteGroup(group.id);
        if (res.ok) {
            onSave();
        } else {
            let body = await res.json();
            err = body.message;
        }
    }

</script>

<div class="data">
    <div class="label">
        Are you sure, you want to delete this group?
    </div>
    <div class="value">
        <div class="btn">
            <Button on:click={onSubmit}>DELETE</Button>
        </div>

        {#if err}
            <div class="err">
                {err}
            </div>
        {/if}
    </div>
</div>

<style>
    .btn {
        width: 5rem;
    }

    .data {
        display: flex;
        flex-direction: column;
        margin: 3px 10px;
    }

    .err {
        display: flex;
        align-items: center;
        margin: 0 10px;
        color: var(--col-err);
    }

    .label {
        height: 30px;
        margin: 0 5px;
        display: flex;
        font-weight: bold;
    }

    .value {
        margin: 5px 0 25px 0;
        display: flex;
        flex-direction: column;
        justify-content: center;
    }
</style>
