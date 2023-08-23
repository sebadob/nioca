<script>
    import PasswordInput from "$lib/inputs/PasswordInput.svelte";
    import * as yup from "yup";
    import Button from "$lib/Button.svelte";
    import {slide} from "svelte/transition";
    import {extractFormErrors} from "../../../utils/helpers.js";
    import {fetchPutPasswordChange} from "../../../utils/dataFetching.js";

    let isLoading = false;
    let success = false;
    let err = '';

    let formValues = {};
    let formErrors = {};
    const schema = yup.object().shape({
        current: yup.string().required('Required').min(16, 'Minimum length: 16 characters').max(128, 'Maximum length: 128 characters'),
        newPwd: yup.string().required('Required').min(16, 'Minimum length: 16 characters').max(128, 'Maximum length: 128 characters'),
        confirm: yup.string().required('Required').min(16, 'Minimum length: 16 characters').max(128, 'Maximum length: 128 characters'),
    });

    async function submit() {
        const isValid = await validateForm();
        if (!isValid) {
            return;
        }

        let data = {
            current_password: formValues.current,
            new_password: formValues.newPwd,
        };

        isLoading = true;

        let res = await fetchPutPasswordChange(data);
        if (res.ok) {
            success = true;
        } else {
            let body = await res.json();
            err = body.message;
        }

        isLoading = false;
    }

    async function validateForm() {
        try {
            await schema.validate(formValues, {abortEarly: false});
            formErrors = {};
            return true;
        } catch (err) {
            formErrors = extractFormErrors(err);
            return false;
        }
    }

</script>

<div class="content">
    <h3>Change Local Password</h3>

    <PasswordInput
            name="current"
            placeholder="Current Password"
            bind:value={formValues.current}
            bind:error={formErrors.current}
    >
        CURRENT PASSWORD
    </PasswordInput>

    <PasswordInput
            autocomplete="new-password"
            name="newPwd"
            placeholder="New Password"
            disabled={!formValues.current}
            bind:value={formValues.newPwd}
            bind:error={formErrors.newPwd}
    >
        NEW PASSWORD
    </PasswordInput>

    <PasswordInput
            autocomplete="new-password"
            name="confirm"
            placeholder="Confirm Password"
            disabled={!formValues.newPwd}
            bind:value={formValues.confirm}
            bind:error={formErrors.confirm}
            showCopy
            on:enter={submit}
    >
        CONFIRM PASSWORD
    </PasswordInput>

    {#if formValues.newPwd !== formValues.confirm}
        <div transition:slide class="err">
            Passwords do not match
        </div>
    {/if}

    <div class="btn">
        <Button bind:isLoading on:click={submit}>
            CHANGE PASSWORD
        </Button>
    </div>

    {#if success}
        <div transition:slide class="ok">
            Success
        </div>
    {:else if err}
        <div transition:slide class="err">
            {err}
        </div>
    {/if}
</div>

<style>
    .btn {
        width: 11rem;
    }

    .err {
        margin-left: .5rem;
        color: var(--col-err);
    }

    .ok {
        margin-left: .5rem;
        color: var(--col-ok);
    }
</style>
