/// Entropie de Shannon d'une chaîne, exprimée en bits par caractère.
///
/// La valeur mesure l'imprévisibilité de la suite de caractères : elle est
/// basse pour un texte répétitif ou lisible, haute pour une suite tirée au
/// hasard, ce qui est le cas d'un secret bien généré.
pub fn shannon(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for byte in value.bytes() {
        counts[byte as usize] += 1;
        total += 1;
    }

    let total = total as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::shannon;

    #[test]
    fn une_chaine_repetitive_a_une_entropie_nulle() {
        assert_eq!(shannon("aaaaaaaa"), 0.0);
    }

    #[test]
    fn un_mot_de_passe_dexemple_reste_sous_le_seuil() {
        assert!(shannon("changeme") < 4.0);
    }

    #[test]
    fn une_cle_aleatoire_depasse_le_seuil() {
        assert!(shannon("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") > 4.0);
    }
}
