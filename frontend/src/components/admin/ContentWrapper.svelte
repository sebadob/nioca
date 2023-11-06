<script>
    import {fade} from "svelte/transition";
    import {adminNavWidth} from "../../stores/adminNav.js";

    const tDur = 200;

    let navWidth = '190px';
    adminNavWidth.subscribe(w => navWidth = `${w}px`);
</script>

<div
        class="content"
        style="left: {navWidth}; width: calc(100vw - {navWidth})"
        in:fade={{delay: tDur, duration: tDur}}
        out:fade={{duration: tDur}}
>
    <slot></slot>
</div>

<style>
    .content {
        position: absolute;
        top: 0;
        height: 100vh;
        display: flex;
        flex-direction: column;
        flex: 1;
        align-items: center;
        overflow-y: auto;
    }
</style>
