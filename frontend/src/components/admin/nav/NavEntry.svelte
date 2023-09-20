<script>
    export let color = 'var(--col-text)';
    export let label = '';
    export let selected = '';

    let hover = false;

    $: if (selected) {
        checkSelected();
    }

    $: {
        if (hover) {
            color = 'var(--col-err)';
        } else {
            checkSelected();
        }
    }

    function checkSelected() {
        if (hover) {
            color = 'var(--col-err)';
        } else if (selected === label) {
            color = 'var(--col-ok)';
        } else {
            color = 'var(--col-text)';
        }
    }
</script>

<div
        role="link"
        tabindex="0"
        class="entry noselect"
        class:selected={selected === label}
        on:click={() => selected = label}
        on:keypress={() => selected = label}
        on:mouseenter={() => hover = true}
        on:mouseleave={() => hover = false}
>
    <slot></slot>
    <span class="label">
    {label}
  </span>
</div>

<style>
    .entry {
        display: flex;
        align-items: center;
        margin: 5px 0;
        font-size: 1.1em;
        color: var(--col-text);
        cursor: pointer;
    }

    .entry:hover {
        color: var(--col-err);
    }

    .label {
        margin-left: 7px;
    }

    .selected {
        color: var(--col-ok);
    }
</style>
