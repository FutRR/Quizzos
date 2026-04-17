  using Microsoft.EntityFrameworkCore;
  using MonAPIDotNet.Data;

  namespace MonAPIDotNet.Service
  {
      public class SeedService
      {
          private readonly MyDbContext _context;

          public SeedService(MyDbContext context)
          {
              _context = context;
          }

          public async Task SeedImpostorWordPairsAsync()
          {
              if (await _context.ImpostorWordPairs.AnyAsync())
              {
                  return; // Déjà rempli
              }

              var wordPairs = new List<ImpostorWordPair>
              {
                  // Objets du quotidien
                  new() { WordA = "Pomme", WordB = "Poire", Category = "Fruits" },
                  new() { WordA = "Table", WordB = "Bureau", Category = "Mobilier" },
                  new() { WordA = "Chaise", WordB = "Tabouret", Category = "Mobilier" },
                  new() { WordA = "Tasse", WordB = "Verre", Category = "Vaisselle" },
                  new() { WordA = "Fourchette", WordB = "Cuillère", Category = "Couverts" },
                  new() { WordA = "Couteau", WordB = "Ciseaux", Category = "Outils" },
                  new() { WordA = "Lampe", WordB = "Lumière", Category = "Éclairage" },
                  new() { WordA = "Téléphone", WordB = "Télévision", Category = "Électronique" },
                  new() { WordA = "Ordinateur", WordB = "Tablette", Category = "Électronique" },
                  new() { WordA = "Clavier", WordB = "Piano", Category = "Musique" },

                  // Animaux
                  new() { WordA = "Chien", WordB = "Loup", Category = "Animaux" },
                  new() { WordA = "Chat", WordB = "Lynx", Category = "Animaux" },
                  new() { WordA = "Lion", WordB = "Tigre", Category = "Animaux" },
                  new() { WordA = "Ours", WordB = "Panda", Category = "Animaux" },
                  new() { WordA = "Dauphin", WordB = "Baleine", Category = "Animaux" },
                  new() { WordA = "Aigle", WordB = "Faucon", Category = "Animaux" },
                  new() { WordA = "Serpent", WordB = "Lézard", Category = "Animaux" },
                  new() { WordA = "Poisson", WordB = "Requin", Category = "Animaux" },
                  new() { WordA = "Papillon", WordB = "Moth", Category = "Animaux" },
                  new() { WordA = "Abeille", WordB = "Guêpe", Category = "Animaux" },

                  // Lieux
                  new() { WordA = "Plage", WordB = "Désert", Category = "Lieux" },
                  new() { WordA = "Montagne", WordB = "Colline", Category = "Lieux" },
                  new() { WordA = "Forêt", WordB = "Jungle", Category = "Lieux" },
                  new() { WordA = "Lac", WordB = "Étang", Category = "Lieux" },
                  new() { WordA = "Rivière", WordB = "Fleuve", Category = "Lieux" },
                  new() { WordA = "Ville", WordB = "Village", Category = "Lieux" },
                  new() { WordA = "Cinéma", WordB = "Théâtre", Category = "Lieux" },
                  new() { WordA = "Restaurant", WordB = "Café", Category = "Lieux" },
                  new() { WordA = "Hôpital", WordB = "Clinique", Category = "Lieux" },
                  new() { WordA = "École", WordB = "Université", Category = "Lieux" },

                  // Métiers
                  new() { WordA = "Docteur", WordB = "Infirmier", Category = "Métiers" },
                  new() { WordA = "Professeur", WordB = "Instituteur", Category = "Métiers" },
                  new() { WordA = "Policier", WordB = "Détective", Category = "Métiers" },
                  new() { WordA = "Pompier", WordB = "Pilote", Category = "Métiers" },
                  new() { WordA = "Cuisinier", WordB = "Boulanger", Category = "Métiers" },
                  new() { WordA = "Peintre", WordB = "Dessinateur", Category = "Métiers" },
                  new() { WordA = "Chanteur", WordB = "Musicien", Category = "Métiers" },
                  new() { WordA = "Acteur", WordB = "Comédien", Category = "Métiers" },
                  new() { WordA = "Jardinier", WordB = "Paysagiste", Category = "Métiers" },
                  new() { WordA = "Mécanicien", WordB = "Ingénieur", Category = "Métiers" },

                  // Véhicules
                  new() { WordA = "Voiture", WordB = "Camion", Category = "Véhicules" },
                  new() { WordA = "Moto", WordB = "Vélo", Category = "Véhicules" },
                  new() { WordA = "Avion", WordB = "Hélicoptère", Category = "Véhicules" },
                  new() { WordA = "Bateau", WordB = "Sous-marin", Category = "Véhicules" },
                  new() { WordA = "Train", WordB = "Tramway", Category = "Véhicules" },

                  // nourriture
                  new() { WordA = "Pizza", WordB = "Tarte", Category = "Nourriture" },
                  new() { WordA = "Hamburger", WordB = "Sandwich", Category = "Nourriture" },
                  new() { WordA = "Salade", WordB = "Soupe", Category = "Nourriture" },
                  new() { WordA = "Gâteau", WordB = "Tarte", Category = "Nourriture" },
                  new() { WordA = "Glaces", WordB = "Sorbet", Category = "Nourriture" },

                  // Concepts / Abstraits
                  new() { WordA = "Amour", WordB = "Passion", Category = "Émotions" },
                  new() { WordA = "Joie", WordB = "Bonheur", Category = "Émotions" },
                  new() { WordA = "Tristesse", WordB = "Mélancolie", Category = "Émotions" },
                  new() { WordA = "Peur", WordB = "Terreur", Category = "Émotions" },
                  new() { WordA = "Rêve", WordB = "Cauchemar", Category = "Émotions" },
              };

              _context.ImpostorWordPairs.AddRange(wordPairs);
              await _context.SaveChangesAsync();
          }
      }
  }
