<script>
    export let label = '';

</script>

<div class="section noselect">
    <div class="label">
        <slot name="logo"></slot>
        <div style="margin-left: 5px;">
            {label}
        </div>
    </div>

    <div class="entries">
        <slot name="entries"></slot>
    </div>
</div>

<style>
    .section {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        margin: 10px 0;
        font-size: 1.1em;
        color: var(--col-text);
    }

    .entries {
        margin-left: 5px;
    }

    .label {
        display: flex;
        align-items: center;
    }
</style>
