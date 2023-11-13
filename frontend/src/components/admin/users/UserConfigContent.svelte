<script>
    import {
        fetchDeleteUserGroupAccess,
        fetchPostUserGroupAccess,
        fetchPutUserGroupAccess
    } from "../../../utils/dataFetching.js";
    import Switch from "$lib/Switch.svelte";
    import {onMount} from "svelte";
    import Button from "$lib/Button.svelte";
    import AccessConfigX509 from "./config/AccessConfigX509.svelte";
    import AccessConfigSsh from "./config/AccessConfigSsh.svelte";

    export let user;
    export let groupsFiltered = [];
    export let accessGroupSelected;
    export let selected;
    export let onSave;

    let err = '';
    let success = false;
    let timer;

    // callback functions
    let validatePrincipals;
    let getKeyUsages;
    let getKeyUsagesExt;

    let formErrors = {};

    $: if (success) {
        timer = setTimeout(() => {
            success = false;
            onSave();
        }, 3000);
    }

    onMount(() => {
        return () => clearTimeout(timer);
    });

    async function onAddNew(group) {
        let res = await fetchPostUserGroupAccess(user.id, group.id);
        if (res.ok) {
            onSave();
            selected = group.id;
        } else {
            let body = await res.json();
            console.error(body.message);
        }
    }

    async function onSubmit() {
        err = '';

        const valid = await validateForm();
        if (!valid || !validatePrincipals()) {
            err = 'Invalid input';
            return;
        }

        let data = accessGroupSelected;
        data.principals = accessGroupSelected.accessSsh.principals.filter(p => p.length > 0);
        data.accessSsh.validSecs = Number.parseInt(accessGroupSelected.accessSsh.validSecs);
        data.accessX509.validHours = Number.parseInt(accessGroupSelected.accessX509.validHours);
        data.accessX509.keyUsage = getKeyUsages();
        data.accessX509.keyUsageExt = getKeyUsagesExt();

        let res = await fetchPutUserGroupAccess(data.userId, data.groupId, data);
        if (res.ok) {
            success = true;
        } else {
            let body = await res.json();
            err = body.message;
        }
    }

    async function onDelete() {
        let res = await fetchDeleteUserGroupAccess(user.id, selected);
        if (res.ok) {
            selected = '';
            onSave();
        }
    }

    async function validateForm() {
        formErrors = {};

        let isValid = true;

        let validSecds = accessGroupSelected.accessSsh.validSecs;
        if (validSecds < 1) {
            formErrors.validSecs = 'Cannot be lower than 1';
            isValid = false;
        }
        if (validSecds > 31536000) {
            formErrors.validSecs = 'Cannot be higher than 31536000';
            isValid = false;
        }

        let validHours = accessGroupSelected.accessX509.validHours;
        if (validHours < 1) {
            formErrors.validHours = 'Cannot be lower than 1';
            isValid = false;
        }
        if (validHours > 175200) {
            formErrors.validHours = 'Cannot be higher than 175200';
            isValid = false;
        }

        return isValid;
    }

</script>

<div class="container">
    {#if selected === '_new_'}
        <div class="inner">
            Choose the group you want to provide access to.
        </div>

        <div class="groups">
            {#each groupsFiltered as group (group.id)}
                <div
                        role="button"
                        tabindex="0"
                        class="group"
                        on:click={onAddNew.bind(this, group)}
                        on:keypress={onAddNew.bind(this, group)}
                >
                    {group.name}
                </div>
            {/each}
        </div>
    {:else if accessGroupSelected}
        <div class="inner">
            <div class="secrets">
                <div class="head">
                    <b>Secrets</b>
                </div>

                <div class="row gap-10">
                    <div class="row gap-05">
                        create
                        <Switch bind:selected={accessGroupSelected.secretCreate}/>
                    </div>
                    <div class="row gap-05">
                        read
                        <Switch bind:selected={accessGroupSelected.secretRead}/>
                    </div>
                    <div class="row gap-05">
                        update
                        <Switch bind:selected={accessGroupSelected.secretUpdate}/>
                    </div>
                    <div class="row gap-05">
                        delete
                        <Switch bind:selected={accessGroupSelected.secretDelete}/>
                    </div>
                </div>
            </div>

            <div class="ssh">
                <div class="head">
                    <b>SSH</b>
                </div>

                <AccessConfigSsh
                        bind:accessSsh={accessGroupSelected.accessSsh}
                        bind:formErrors
                        bind:validatePrincipals
                />
            </div>

            <div class="x509">
                <div class="head">
                    <b>X509</b>
                </div>

                <AccessConfigX509
                        bind:accessX509={accessGroupSelected.accessX509}
                        bind:formErrors
                        bind:getKeyUsages
                        bind:getKeyUsagesExt
                />
            </div>

            <div class="data row gap-10">
                <div class="btn">
                    <Button on:click={onSubmit} level={1}>SAVE</Button>
                </div>

                <div class="btn">
                    <Button on:click={onDelete} level={3}>DELETE</Button>
                </div>

                {#if success}
                    <div class="success">
                        Success
                    </div>
                {/if}

                {#if err}
                    <div class="mainErr err">
                        {err}
                    </div>
                {/if}
            </div>
        </div>
    {:else}
        <div class="inner">
            Select a group or add a new access config
        </div>
    {/if}
</div>

<style>
    .container {
        max-height: 34.5rem;
        width: 100%;
        overflow-y: auto;
        border-left: 1px solid var(--col-gmid);
    }

    .err {
        color: var(--col-err);
    }

    .gap-05 {
        gap: .5rem;
    }

    .gap-10 {
        gap: 1rem;
    }

    .groups {
        margin: .5rem 0;
        display: flex;
        flex-direction: column;
    }

    .group {
        cursor: pointer;
        padding: .125rem .5rem;
    }

    .group:hover {
        background: var(--col-gmid);
    }

    .head {
        margin-bottom: .5rem;
    }

    .inner {
        padding: .5rem;
    }

    .row {
        display: flex;
        align-items: center;
    }

    .ssh {
        margin: 1rem 0;
    }

    .success {
        color: var(--col-ok);
    }
</style>
